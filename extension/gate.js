import {cleanUrl} from './common.js';
const $=s=>document.querySelector(s);
const send=async message=>{const result=await chrome.runtime.sendMessage(message);if(result.error)throw new Error(result.error);return result.value;};
let destination;
async function show(verdict) {
  $('#destination').textContent=verdict.url;
  $('#reason').textContent=verdict.reason;
  $('#evidence').textContent=`Categories: ${verdict.categories.join(', ')} · policy revision ${verdict.revision}`;
  if(verdict.action==='block') {$('#title').textContent='This page is blocked.';$('#retry').hidden=false;return;}
  if(verdict.action==='allow') {
    $('#title').textContent='Destination checked.';
    const latest=await send({type:'continue',url:verdict.url});
    if(latest.action!=='allow') await show(latest);
    return;
  }
  $('#title').textContent='Sanitized reader';
  const result=await send({type:'reader',url:verdict.url});
  if(result.verdict.action!=='sanitize') return show(result.verdict);
  // This document's CSP disables every network resource. Parsed HTML never enters
  // the live DOM. Only text nodes and freshly-created checked links are rendered.
  const doc=new DOMParser().parseFromString(result.html,'text/html');
  doc.querySelectorAll('script,style,iframe,object,embed,form,input,button,textarea,select,svg,math,template,noscript').forEach(el=>el.remove());
  const source=doc.querySelector('main,article') || doc.body;
  const evaluated=await send({type:'classify-reader',url:verdict.url,text:source.textContent.slice(0,32000)});
  if(evaluated.action==='block') return show(evaluated);
  $('#reader').replaceChildren();
  const text=document.createElement('div');text.className='reader-text';text.textContent=source.textContent.slice(0,100000);$('#reader').append(text);
  const links=document.createElement('ul');
  for(const original of [...source.querySelectorAll('a[href]')].slice(0,100)) {
    try {
      const url=cleanUrl(new URL(original.getAttribute('href'),verdict.url).href);
      const a=document.createElement('a');a.textContent=original.textContent.trim().slice(0,200) || url;a.href=`${chrome.runtime.getURL('gate.html')}#${url}`;
      const li=document.createElement('li');li.append(a);links.append(li);
    } catch { /* Unsupported schemes never become reader links. */ }
  }
  $('#reader').append(links);
  $('#reason').textContent='Text and checked links only. Scripts, forms, images, frames, and embedded media are excluded.';
}
async function run() {
  $('#retry').hidden=true;$('#reader').replaceChildren();
  try {
    destination=location.hash.slice(1) || await send({type:'pending'});
    if(!destination) throw new Error('No destination was supplied. Open a web address to check it.');
    destination=cleanUrl(destination);
    await show(await send({type:'check',url:destination}));
  } catch(error) {$('#title').textContent='Navigation paused.';$('#reason').textContent=error.message;$('#retry').hidden=false;}
}
$('#retry').addEventListener('click',run);
window.addEventListener('hashchange',run);
run();
