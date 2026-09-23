// One independent poller for all TPS cards. Failures never block load controls.
export function initThroughput(api) {
  let timer, controller, active=false, generation=0;
  function render(data) {
    const available=data?.status==='available' && Number.isFinite(data.tokens_per_second) && data.tokens_per_second>=0;
    const value=available?data.tokens_per_second.toLocaleString('ru-RU',{maximumFractionDigits:1,minimumFractionDigits:1})+' токен/с':'—';
    const messages={not_configured:'Prometheus не настроен',no_data:'Нет замеров: проверьте backend или дождитесь сбора метрик',unavailable:'Метрики временно недоступны'};
    const status=available?'Среднее за 1 мин · обновлено '+new Date(data.evaluated_at).toLocaleTimeString('ru-RU'):(messages[data?.status]||messages.unavailable);
    document.querySelectorAll('[data-tps-value]').forEach(el=>el.textContent=value);
    document.querySelectorAll('[data-tps-status]').forEach(el=>el.textContent=status);
  }
  async function poll() {
    if(!active)return;
    const current=generation;
    controller=new AbortController();
    try {
      const data=await api('/api/v1/metrics/throughput',{signal:controller.signal});
      if(active && current===generation)render(data);
    } catch {
      if(active && current===generation)render({status:'unavailable'});
    } finally {
      if(active && current===generation)timer=setTimeout(poll,5000);
    }
  }
  return {
    start() {
      if (active) {
        return;
      }
      active=true;
      generation++;
      poll();
    },
    stop() {
      active=false;
      generation++;
      clearTimeout(timer);
      controller?.abort();
      render(null);
    },
  };
}
