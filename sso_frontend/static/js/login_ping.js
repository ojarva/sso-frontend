function ping_login() {
 i = new Image();
 i.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime();
}
setInterval(ping_login, 120000);
