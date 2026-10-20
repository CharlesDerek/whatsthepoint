import test from 'node:test';
import assert from 'node:assert/strict';
import {cleanUrl,portalOrigin,classify,exactRule} from '../../extension/common.js';
test('URL checks reject unsafe schemes, credentials, and nonlocal plaintext portals',()=>{
  for(const url of ['javascript:alert(1)','file:///etc/passwd','data:text/html,test','https://u:p@example.com/']) assert.throws(()=>cleanUrl(url));
  assert.throws(()=>portalOrigin('http://portal.example.com'));
  assert.throws(()=>portalOrigin('https://portal.example.com/path'));
  assert.equal(portalOrigin('http://127.0.0.1:18080'),'http://127.0.0.1:18080');
  assert.equal(cleanUrl('https://example.com/path?utm_source=ad&q=keep#fragment'),'https://example.com/path?q=keep');
  assert.equal(cleanUrl('https://example.com/?signed=a%20b'),'https://example.com/?signed=a%20b');
});
test('category phrases use distinct whole-word evidence',()=>{
  const categories=[{id:'gambling',terms:['online casino','bet now'],threshold:2}];
  assert.deepEqual(classify('ONLINE CASINO! Bet now.',categories),['gambling']);
  assert.deepEqual(classify('online casino online casino',categories),[]);
  assert.deepEqual(classify('notonline casinos bet nowish',categories),[]);
});
test('navigation permits match only the exact checked URL, tab and method',()=>{
  const url='https://example.com/a+b?q=a.b';
  const rule=exactRule(123,42,url);
  const regex=new RegExp(rule.condition.regexFilter);
  assert.ok(regex.test(url));
  for(const other of ['https://example.com/aab?q=a.b','https://exampleXcom/a+b?q=a.b',url+'&extra=x',url+'/secret']) assert.equal(regex.test(other),false);
  assert.deepEqual(rule.condition.tabIds,[42]);
  assert.deepEqual(rule.condition.requestMethods,['get']);
  assert.deepEqual(rule.condition.resourceTypes,['main_frame']);
});
