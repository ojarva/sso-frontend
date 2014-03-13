(function() {
try {
    function get_timestamp() {
        return (new Date()).getTime();
    }
    var login_window_current_status = "unknown";
    var login_ping_timeout;
    var login_ping_last_sent = get_timestamp() - 350000;
    var login_ping_counter = 0;
    var user_activity;
    var tab_id = Math.random();

    if (window.jQuery) {
      window.jQuery(window).focus(function(evt) {
        onchange(evt);
      });
      window.jQuery(window).blur(function(evt) {
        onchange(evt);
      });
      window.jQuery(window).mouseover(function(evt) {
       update_user_activity(evt);
      });
      window.jQuery(window).keyup(function(evt) {
       update_user_activity(evt);
      });
    } else {
      document.onfocusin = document.onfocusout = onchange;
      window.onfocus = window.onblur = onchange;
    }
    function update_user_activity(evt) {
     user_activity = get_timestamp();
     login_ping_update(true);
    }
    function onchange (evt) {
        evt = evt || window.event;
        login_window_current_status = ""+(new Date()).getTime()+"_"+evt.type;
        login_ping_update(true);
    }

    var login_ping_image = new Image();
    function login_ping_update(is_event) {
        var since_last = get_timestamp() - login_ping_last_sent;
        if (since_last < 30000) {
            clearTimeout(login_ping_timeout);
            if (is_event) {
                login_ping_timeout = setTimeout(login_ping_update, 60000 - since_last);
            } else {
                login_ping_timeout = setTimeout(login_ping_update, 300000 - since_last);
            }
            return;
        }
        var hidden = "unknown";
        if ("hidden" in document) {
            hidden = document.hidden;
        }
        login_ping_image.src = "https://login.futurice.com/ping/external/img?location="+encodeURIComponent(window.location)+"&t="+(new Date()).getTime()+"&activity="+login_window_current_status+"&hidden="+hidden+"&c="+login_ping_counter+"&r="+tab_id+"&u="+user_activity;
        login_ping_counter += 1;
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
