(function(){
  var root=document.documentElement;
  function setTheme(t){root.setAttribute('data-theme',t);try{localStorage.setItem('theme',t)}catch(e){}
    var m=document.querySelector('meta[name=theme-color]');if(m)m.content=t==='dark'?'#000000':'#ffffff';}
  var tb=document.getElementById('theme');
  if(tb)tb.addEventListener('click',function(){setTheme(root.getAttribute('data-theme')==='dark'?'light':'dark')});
  var mq=window.matchMedia('(prefers-color-scheme: dark)');
  mq.addEventListener&&mq.addEventListener('change',function(e){var s;try{s=localStorage.getItem('theme')}catch(x){}if(!s)setTheme(e.matches?'dark':'light')});
  var mb=document.getElementById('menu'),nl=document.getElementById('links');
  if(mb&&nl){mb.addEventListener('click',function(){var o=nl.classList.toggle('open');mb.setAttribute('aria-expanded',o)});
    nl.addEventListener('click',function(e){if(e.target.tagName==='A'){nl.classList.remove('open');mb.setAttribute('aria-expanded',false)}})}
  var els=document.querySelectorAll('.rv');
  if('IntersectionObserver' in window){var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},{threshold:.12});els.forEach(function(el){io.observe(el)})}
  else els.forEach(function(el){el.classList.add('in')});
  document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){
    var t=b.getAttribute('data-copy'),o=b.textContent;
    (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent=o},1600)},function(){b.textContent='Press Ctrl+C';setTimeout(function(){b.textContent=o},1600)})})});
  var y=document.getElementById('year');if(y)y.textContent=new Date().getFullYear();
})();
