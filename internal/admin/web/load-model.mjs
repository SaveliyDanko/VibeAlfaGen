export const activeStates = new Set(['pending', 'running', 'stopping']);

export function reportMetrics(report) {
  const seconds = (Date.parse(report.finished_at) - Date.parse(report.started_at)) / 1000;
  const counts = report.counts || {};
  return {
    counts, seconds: seconds > 0 ? seconds : null,
    httpRPS: seconds > 0 ? (counts.http_requests ?? counts.sent_requests ?? 0) / seconds : null,
    operationRPS: seconds > 0 ? (counts.successful_operations ?? 0) / seconds : null,
    latency: report.latency_ms || {},
  };
}

export function reportIsCurrent(test, report) {
  return !!test?.config?.run_id && test.config.run_id === report?.run_id;
}

export function progressPercent(progress) {
  if (!progress) return null;
  const ratios = [];
  if (progress.duration_seconds > 0) ratios.push(progress.elapsed_seconds / progress.duration_seconds);
  if (progress.operation_limit > 0) ratios.push(progress.counts.planned_operations / progress.operation_limit);
  return ratios.length ? Math.min(100, Math.max(0, ...ratios) * 100) : null;
}

const labels = {
  idle: 'Готов к запуску', pending: 'Ожидание запуска', running: 'Выполняется',
  stopping: 'Останавливается', stopped: 'Остановлен', completed: 'Завершён',
  failed: 'Ошибка прогона', interrupted: 'Прерван перезапуском', unavailable: 'Генератор недоступен',
};
const descriptions = {
  idle: 'Настройте сценарий и нажмите «Запустить».',
  pending: 'Команда сохранена. Ожидаем подтверждение генератора; обычно это занимает несколько секунд.',
  running: 'Показатели обновляются автоматически каждые 2 секунды.',
  stopping: 'Команда остановки отправлена. Ожидаем завершение текущих запросов и отчёт.',
  stopped: 'Прогон остановлен. Для нового прогона нажмите «Запустить».',
  completed: 'Прогон завершён. Итоговая оценка и показатели приведены в отчёте.',
  failed: 'Прогон завершился с ошибкой. Проверьте HTTP-коды и итоговый отчёт.',
  interrupted: 'Процесс генератора перезапускался. Прогон автоматически не повторяется; его можно запустить заново.',
  unavailable: 'Нет свежего сигнала от генератора более 10 секунд. Проверьте процесс mock-client и общий каталог статуса.',
};
const failures = {
  configuration: 'Генератор отклонил настройки или не смог прочитать API-ключ. Проверьте систему, её ключ и параметры теста.',
  tls: 'Не удалось настроить TLS. Проверьте сертификат, ключ клиента и доверенный CA генератора.',
  report_or_requests: 'Прогон завершился с ошибками запросов либо не удалось записать отчёт. Проверьте HTTP-коды и журналы генератора.',
};

export function runPresentation(status = {}) {
  const name = status.state || 'unavailable';
  let kind = 'warn';
  if (name === 'running' || name === 'completed') kind = 'ok';
  else if (name === 'failed' || name === 'unavailable') kind = 'bad';
  return {
    label: labels[name] || name,
    description: failures[status.failure_code] || descriptions[name] || 'Неизвестное состояние генератора.',
    kind,
  };
}

export function verdictDescription(report) {
  if (report.stop_reason === 'five_consecutive_invalid') return 'Остановка после пяти подряд некорректных ответов. Проверьте доступ и HTTP-коды ниже.';
  if (report.verdict === 'CANCELLED') return 'Прогон остановлен до окончания.';
  if (report.verdict === 'HARNESS_ERROR') return 'Есть ошибки запросов или проверки ответов. Сверьте HTTP-коды, тайм-ауты и выбранную систему.';
  if (report.verdict === 'SLO_MISSED') return 'Прогон завершён, но цель производительности не достигнута. Проверьте пропуски, скорость и задержки.';
  return report.verdict === 'PASS' ? 'Критерии этого прогона выполнены.' : 'Итог последнего сохранённого прогона.';
}
