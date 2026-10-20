const $=s=>document.querySelector(s);
const send=async message=>{const result=await chrome.runtime.sendMessage(message);if(result.error)throw new Error(result.error);return result.value;};
async function refresh() {
  const config=await send({type:'settings'});
  $('#portal').value=config.portal || '';
  $('#native').checked=!!config.requireNative;
  for(const el of $('#enrollment').elements) el.disabled=config.managed;
  $('#status').textContent=config.policy ? `Enrolled as ${config.policy.profile.name} · revision ${config.policy.revision}${config.managed?' · managed by administrator':''}` : config.error;
  $('#identity').textContent=config.identity ? `Desktop identity\n${JSON.stringify(config.identity,null,2)}` : 'Native identity companion is not registered.';
}
$('#enrollment').addEventListener('submit',async event=>{
  event.preventDefault();
  try {await send({type:'enroll',portal:$('#portal').value,token:$('#token').value,requireNative:$('#native').checked});$('#token').value='';await refresh();}
  catch(error){$('#status').textContent=error.message;}
});
refresh().catch(error=>{$('#status').textContent=error.message;});
