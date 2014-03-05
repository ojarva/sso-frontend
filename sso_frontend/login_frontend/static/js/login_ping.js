var login_ping_image = new Image();
function login_ping_update() {
 login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime();
}
setInterval(ping_login_update, 120000);
