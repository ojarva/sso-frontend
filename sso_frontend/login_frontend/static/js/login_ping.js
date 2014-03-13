(function() {
try {
    function get_timestamp() {
        return (new Date()).getTime();
    }
    var login_window_current_status = "unknown";
    var login_ping_timeout;
    var login_ping_last_sent = get_timestamp() - 350000;
    document.onfocusin = document.onfocusout = onchange;
    window.onfocus = window.onblur = onchange;
    function onchange (evt) {
        evt = evt || window.event;
        login_window_current_status = ""+(new Date()).getTime()+"_"+evt.type;
        login_ping_update();
    }   
    var login_ping_image = new Image();
    function login_ping_update() {
        var since_last = get_timestamp() - login_ping_last_sent;
        if (since_last < 30000) {
            clearTimeout(login_ping_timeout);
            login_ping_timeout = setTimeout(login_ping_update, 300000 - since_last);
            return;
        }
        var hidden = "unknown";
        if ("hidden" in document) {
            hidden = document.hidden;
        }
        login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime()+"&activity="+login_window_current_status+"&hidden="+hidden;
        clearTimeout(login_ping_timeout);
        login_ping_last_sent = get_timestamp();
        login_ping_timeout = setTimeout(login_ping_update, 300000);
    }
    login_ping_update();

} catch(e) {
    i = new Image();
    i.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime()+"&error="+encodeURIComponent(""+e);
}
})();
