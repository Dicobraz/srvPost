/*
  Подсветка совпадений в открытом письме (WEB-05, F3/Shift+F3): iframe письма — sandboxed без
  allow-same-origin (sanitize.ts), поэтому в srcdoc-документ встраивается мини-скрипт, который
  обходит текстовые узлы, оборачивает совпадения в <mark> и двигает текущее совпадение по командам
  родителя (postMessage — allow-scripts есть; состояние совпадений скрипт шлёт родителю обратно).
  Термы — из активного поиска (search.ts highlightTerms); письмо, открытое не из поиска, скрипт
  не получает и подсветки не ставит.
*/

/** Стиль подсветки srcdoc-документа: янтарный — из таблицы макета (сроки — только янтарный). */
export const HIGHLIGHT_STYLE =
  "mark.search-hit{background:#F8DEA8;color:#161616}mark.search-hit-cur{background:#E4A100;outline:2px solid #9A6F00}";

/**
 * Мини-скрипт srcdoc-документа: подсветка терминов и навигация F3. Обход — TreeWalker по
 * текстовым узлам (script/style/mark пропускаются), совпадения — <mark class="search-hit">,
 * текущее — дополнительно search-hit-cur + scrollIntoView. Родителю — {type:"hl-state"}.
 */
export function highlightScript(terms: string[]): string {
  // Термы — данные, не код: JSON.stringify внутри литерала скрипта (кавычки экранированы JSON'ом).
  return `(function(){
var TERMS=${JSON.stringify(terms.slice(0, 8))};
var CLASS="search-hit",CUR="search-hit-cur",marks=[],cur=-1;
function esc(s){return s.replace(/[.*+?^\${}()|[\\]\\\\]/g,"\\\\$&")}
function report(){try{parent.postMessage({type:"hl-state",count:marks.length,index:cur},"*")}catch(e){}}
function clear(){for(var i=0;i<marks.length;i++){var mk=marks[i],p=mk.parentNode;if(!p)continue;mk.replaceWith(document.createTextNode(mk.textContent));p.normalize()}marks=[];cur=-1}
function build(){
  clear();
  if(!TERMS.length){report();return}
  var pattern=TERMS.map(esc).join("|");
  var find=new RegExp("("+pattern+")","gi"),test=new RegExp("("+pattern+")","i");
  var walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,{acceptNode:function(n){
    if(!n.nodeValue||!n.nodeValue.trim())return NodeFilter.FILTER_REJECT;
    var p=n.parentNode;
    if(p&&(p.nodeName==="SCRIPT"||p.nodeName==="STYLE"||p.nodeName==="MARK"))return NodeFilter.FILTER_REJECT;
    return test.test(n.nodeValue)?NodeFilter.FILTER_ACCEPT:NodeFilter.FILTER_REJECT;
  }});
  var nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
  nodes.forEach(function(n){
    var text=n.nodeValue;find.lastIndex=0;
    var frag=document.createDocumentFragment(),last=0,m;
    while((m=find.exec(text))){
      if(m.index>last)frag.appendChild(document.createTextNode(text.slice(last,m.index)));
      var mk=document.createElement("mark");mk.className=CLASS;mk.textContent=m[0];frag.appendChild(mk);
      marks.push(mk);last=m.index+m[0].length;
      if(m[0].length===0)find.lastIndex++;
    }
    if(last<text.length)frag.appendChild(document.createTextNode(text.slice(last)));
    n.parentNode.replaceChild(frag,n);
  });
  report();
}
function show(i){
  if(!marks.length)return;
  if(cur>=0&&marks[cur])marks[cur].className=CLASS;
  cur=((i%marks.length)+marks.length)%marks.length;
  var mk=marks[cur];mk.className=CLASS+" "+CUR;
  try{mk.scrollIntoView({block:"center"})}catch(e){}
  report();
}
window.addEventListener("message",function(e){
  var d=e.data||{};
  if(d.type==="hl-next")show(cur+1);
  else if(d.type==="hl-prev")show(cur-1);
});
build();
})();`;
}

/** Тип сообщения состояния подсветки из iframe (hl-state) — принимает страница почты. */
export interface HlStateMessage {
  type: "hl-state";
  count: number;
  index: number;
}

/** Является ли событие сообщением состояния подсветки. */
export function isHlState(data: unknown): data is HlStateMessage {
  return (
    typeof data === "object" && data !== null &&
    (data as HlStateMessage).type === "hl-state" &&
    typeof (data as HlStateMessage).count === "number" &&
    typeof (data as HlStateMessage).index === "number"
  );
}

/** Команда iframe письма: следующее/предыдущее совпадение (F3/Shift+F3). */
export function sendHlCommand(frame: HTMLIFrameElement | null, command: "hl-next" | "hl-prev"): void {
  frame?.contentWindow?.postMessage({ type: command }, "*");
}
