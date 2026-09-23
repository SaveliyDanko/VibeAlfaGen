package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/alfagen/pii-service/internal/pii"
)

const (
	// ScenarioRequest preserves the original one-request load behavior.
	ScenarioRequest = "request"
	// ScenarioMaskOnly validates that a new process request returns a mask.
	ScenarioMaskOnly = "mask_only"
	// ScenarioRoundTrip evaluates original -> mask -> original pairs.
	ScenarioRoundTrip = "round_trip"
	// ScenarioStableRetry validates idempotent masking for the same payload ID.
	ScenarioStableRetry = "stable_retry"
	// ScenarioExpectedConflict validates the third-content 409 state transition.
	ScenarioExpectedConflict = "expected_conflict"
	// ScenarioMixed deterministically selects one of the stateful scenarios.
	ScenarioMixed = "mixed"

	maskDatasetSchema  = "alfagen.mask-eval.v1"
	maxMaskDatasetSize = 32 << 20
)

// MaskSpan is an expected PII byte span in the original UTF-8 payload. Type is
// reporting metadata only and never becomes a Prometheus label.
type MaskSpan struct {
	Type  string `json:"type"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// MaskFixture contains one independent synthetic quality evaluation item.
// Name, payload and expected mask are intentionally excluded from reports.
type MaskFixture struct {
	Name         string     `json:"name"`
	Payload      string     `json:"payload"`
	ExpectedMask string     `json:"expected_mask"`
	Spans        []MaskSpan `json:"spans"`
	// Raw load datasets have no masking oracle and may contain no PII.
	allowUnchanged bool
}

func (f MaskFixture) rejectsUnchanged(mask string) bool {
	return !f.allowUnchanged && mask == f.Payload
}

type maskDataset struct {
	Schema     string        `json:"schema"`
	OffsetUnit string        `json:"offset_unit"`
	Synthetic  bool          `json:"synthetic"`
	Entries    []MaskFixture `json:"entries"`
}

var supportedMaskSpanTypes = func() map[string]struct{} {
	types := make(map[string]struct{}, len(pii.AllTypes))
	for _, typ := range pii.AllTypes {
		types[string(typ)] = struct{}{}
	}
	return types
}()

// LoadMaskDataset strictly validates a synthetic, annotated mask-evaluation
// dataset. Offsets are byte offsets, matching the detector/API contract.
func LoadMaskDataset(path string) ([]MaskFixture, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMaskDatasetSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > maxMaskDatasetSize {
		return nil, "", errors.New("mask dataset exceeds 32 MiB")
	}
	var dataset maskDataset
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dataset); err != nil {
		return nil, "", fmt.Errorf("invalid mask dataset: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, "", errors.New("invalid mask dataset: expected one JSON document")
	}
	if dataset.Schema != maskDatasetSchema || dataset.OffsetUnit != "utf8_bytes" || !dataset.Synthetic || len(dataset.Entries) == 0 || len(dataset.Entries) > 10000 {
		return nil, "", errors.New("unsupported mask dataset")
	}
	seen := make(map[string]bool, len(dataset.Entries))
	entries := make([]MaskFixture, len(dataset.Entries))
	for i := range dataset.Entries {
		entry := dataset.Entries[i]
		if entry.Name == "" || len(entry.Name) > 128 || seen[entry.Name] {
			return nil, "", fmt.Errorf("invalid mask dataset entry %d name", i)
		}
		if entry.ExpectedMask == "" {
			return nil, "", fmt.Errorf("invalid mask dataset entry %d: expected_mask is required", i)
		}
		seen[entry.Name] = true
		if err := validateMaskFixture(entry); err != nil {
			return nil, "", fmt.Errorf("invalid mask dataset entry %d: %w", i, err)
		}
		entry.Spans = append([]MaskSpan(nil), entry.Spans...)
		entries[i] = entry
	}
	sum := sha256.Sum256(raw)
	return entries, hex.EncodeToString(sum[:]), nil
}

// LoadReliabilityDataset converts the project's strict synthetic JSONL eval
// corpus into round-trip fixtures. Expected masks are intentionally omitted:
// this profile verifies mask availability and exact demasking while reporting
// coverage of every category, independently of the quality-distance gate.
func LoadReliabilityDataset(path string) ([]MaskFixture, string, error) {
	raw, err := readReliabilityDataset(path)
	if err != nil {
		return nil, "", err
	}
	entries := make([]MaskFixture, 0, 256)
	seenNames := map[string]bool{}
	covered := map[string]bool{}
	for lineNumber, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		entry, err := readReliabilityEntry(line, lineNumber)
		if err != nil {
			return nil, "", err
		}
		if len(entry.Expected) == 0 {
			continue
		}
		if entry.ID == "" || entry.Text == "" || seenNames[entry.ID] {
			return nil, "", fmt.Errorf("invalid reliability dataset entry on line %d", lineNumber+1)
		}
		seenNames[entry.ID] = true
		fixture, err := reliabilityFixture(entry, lineNumber, covered)
		if err != nil {
			return nil, "", err
		}
		entries = append(entries, fixture)
	}
	if len(entries) == 0 {
		return nil, "", errors.New("reliability dataset has no positive entries")
	}
	if err := checkReliabilityCoverage(covered); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return entries, hex.EncodeToString(sum[:]), nil
}

func occurrenceIndex(text, value string, occurrence int) int {
	offset := 0
	for current := 0; current <= occurrence; current++ {
		index := strings.Index(text[offset:], value)
		if index < 0 {
			return -1
		}
		if current == occurrence {
			return offset + index
		}
		offset += index + len(value)
	}
	return -1
}

func validateMaskFixture(entry MaskFixture) error {
	if entry.Payload == "" || !utf8.ValidString(entry.Payload) || !utf8.ValidString(entry.ExpectedMask) {
		return errors.New("payload must be non-empty UTF-8 and expected_mask, when present, must be UTF-8")
	}
	if len(entry.Payload) > 4<<20 || len(entry.ExpectedMask) > 4<<20 {
		return errors.New("payload or expected_mask exceeds 4 MiB")
	}
	if len(entry.Spans) == 0 {
		return errors.New("at least one PII span is required")
	}
	previousEnd := 0
	for i, span := range entry.Spans {
		if _, supported := supportedMaskSpanTypes[span.Type]; !supported {
			return fmt.Errorf("span %d has invalid type", i)
		}
		if span.Start < previousEnd || span.Start < 0 || span.End <= span.Start || span.End > len(entry.Payload) {
			return fmt.Errorf("span %d is invalid or overlaps", i)
		}
		if !utf8.RuneStart(entry.Payload[span.Start]) || (span.End < len(entry.Payload) && !utf8.RuneStart(entry.Payload[span.End])) {
			return fmt.Errorf("span %d is not on a UTF-8 boundary", i)
		}
		previousEnd = span.End
	}
	return nil
}

// NormalizedSpanLevenshtein compares the complete masks, then normalizes the
// Unicode edit distance by the annotated PII size instead of the whole payload.
// Non-PII corruption is still penalized and the result is capped at 1.
func NormalizedSpanLevenshtein(fixture MaskFixture, actualMask string) (float64, error) {
	if err := validateMaskFixture(fixture); err != nil {
		return 0, err
	}
	if fixture.ExpectedMask == "" {
		return 0, errors.New("expected_mask is required for quality distance")
	}
	if !utf8.ValidString(actualMask) {
		return 0, errors.New("actual mask is not UTF-8")
	}
	budget := 0
	for _, span := range fixture.Spans {
		budget += utf8.RuneCountInString(fixture.Payload[span.Start:span.End])
	}
	if budget == 0 {
		return 0, errors.New("PII span budget is empty")
	}
	distance := levenshteinAtMost([]rune(fixture.ExpectedMask), []rune(actualMask), budget)
	return float64(distance) / float64(budget), nil
}

// levenshteinAtMost returns min(exact distance, limit). Common prefix/suffix
// trimming and a diagonal band keep long mostly-equal masks bounded by the PII
// budget rather than quadratic in the complete payload length.
func levenshteinAtMost(left, right []rune, limit int) int {
	if limit <= 0 {
		return 0
	}
	for len(left) > 0 && len(right) > 0 && left[0] == right[0] {
		left, right = left[1:], right[1:]
	}
	for len(left) > 0 && len(right) > 0 && left[len(left)-1] == right[len(right)-1] {
		left, right = left[:len(left)-1], right[:len(right)-1]
	}
	if len(left) == 0 {
		return min(len(right), limit)
	}
	if len(right) == 0 {
		return min(len(left), limit)
	}
	if absInt(len(left)-len(right)) >= limit {
		return limit
	}

	return bandedDistance(left, right, limit)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

type qualityAccumulator struct {
	mu         sync.Mutex
	count      int64
	sum        float64
	max        float64
	categories map[string]int64
}

func (q *qualityAccumulator) record(distance float64, spans []MaskSpan) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.count++
	q.sum += distance
	if distance > q.max {
		q.max = distance
	}
	q.recordCategoriesLocked(spans)
}

func (q *qualityAccumulator) recordCategories(spans []MaskSpan) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.recordCategoriesLocked(spans)
}

func (q *qualityAccumulator) recordCategoriesLocked(spans []MaskSpan) {
	if q.categories == nil {
		q.categories = map[string]int64{}
	}
	seen := map[string]bool{}
	for _, span := range spans {
		if !seen[span.Type] {
			q.categories[span.Type]++
			seen[span.Type] = true
		}
	}
}

func (q *qualityAccumulator) snapshot() (int64, float64, float64, map[string]int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	categories := make(map[string]int64, len(q.categories))
	for key, value := range q.categories {
		categories[key] = value
	}
	mean := float64(0)
	if q.count > 0 {
		mean = q.sum / float64(q.count)
	}
	return q.count, mean, q.max, categories
}

type reliabilityExpected struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Occurrence int    `json:"occurrence"`
}
type reliabilityEntry struct {
	ID       string                `json:"id"`
	Text     string                `json:"text"`
	Expected []reliabilityExpected `json:"expected"`
}

func readReliabilityEntry(line []byte, lineNumber int) (reliabilityEntry, error) {
	var entry reliabilityEntry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		return reliabilityEntry{}, fmt.Errorf("invalid reliability dataset line %d: %w", lineNumber+1, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return reliabilityEntry{}, fmt.Errorf("invalid reliability dataset line %d: expected one JSON object", lineNumber+1)
	}
	return entry, nil
}

func reliabilityFixture(entry reliabilityEntry, lineNumber int, covered map[string]bool) (MaskFixture, error) {
	fixture := MaskFixture{Name: entry.ID, Payload: entry.Text}
	for _, expected := range entry.Expected {
		if _, ok := supportedMaskSpanTypes[expected.Type]; !ok || expected.Value == "" || expected.Occurrence < 0 {
			return MaskFixture{}, fmt.Errorf("invalid reliability expectation on line %d", lineNumber+1)
		}
		start := occurrenceIndex(entry.Text, expected.Value, expected.Occurrence)
		if start < 0 {
			return MaskFixture{}, fmt.Errorf("reliability expectation not found on line %d", lineNumber+1)
		}
		fixture.Spans = append(fixture.Spans, MaskSpan{Type: expected.Type, Start: start, End: start + len(expected.Value)})
		covered[expected.Type] = true
	}
	sort.Slice(fixture.Spans, func(i, j int) bool { return fixture.Spans[i].Start < fixture.Spans[j].Start })
	if err := validateMaskFixture(fixture); err != nil {
		return MaskFixture{}, fmt.Errorf("invalid reliability dataset entry %q: %w", entry.ID, err)
	}
	return fixture, nil
}

func checkReliabilityCoverage(covered map[string]bool) error {
	missing := make([]string, 0)
	for typ := range supportedMaskSpanTypes {
		if !covered[typ] {
			missing = append(missing, typ)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("reliability dataset misses categories: %s", strings.Join(missing, ", "))
	}
	return nil
}

func bandedDistance(left, right []rune, limit int) int {
	// Keep the row on the shorter dimension.
	if len(right) > len(left) {
		left, right = right, left
	}
	width := len(right)
	previous := make([]int, width+1)
	current := make([]int, width+1)
	for j := range previous {
		previous[j] = min(j, limit)
	}
	band := limit - 1 // Values outside this band cannot produce distance < limit.
	for i := 1; i <= len(left); i++ {
		from := max(1, i-band)
		to := min(width, i+band)
		current[0] = min(i, limit)
		if from > 1 {
			current[from-1] = limit
		}
		for j := from; j <= to; j++ {
			cost := 1
			if left[i-1] == right[j-1] {
				cost = 0
			}
			current[j] = min(limit, min(previous[j]+1, min(current[j-1]+1, previous[j-1]+cost)))
		}
		if to < width {
			current[to+1] = limit
		}
		previous, current = current, previous
	}
	return min(previous[width], limit)
}

func readReliabilityDataset(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMaskDatasetSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMaskDatasetSize {
		return nil, errors.New("reliability dataset exceeds 32 MiB")
	}
	return raw, nil
}
