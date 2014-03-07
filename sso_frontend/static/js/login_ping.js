var login_ping_image = new Image();
login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime();
function login_ping_update() {
 login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime();
}
setInterval(login_ping_update, 300000);
