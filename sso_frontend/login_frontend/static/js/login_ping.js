var login_ping_image = new Image();
function login_ping_update() {
 login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime();
}
login_ping_update();
setInterval(login_ping_update, 300000);
