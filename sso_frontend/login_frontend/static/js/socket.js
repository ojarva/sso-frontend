var socket;
$(document).ready(function (){
 var rand_id = Math.random();
 socket = io.connect('https://login.futurice.com');
 socket.on("connect", function() {
   bid_public = $.cookie("v2public-browserid");
   if (bid_public) {
     socket.emit("authenticate", { "bid_public": bid_public, "tab_id": rand_id });
   }
 });
 socket.on('server_event', function (data) {
    try {
      parsed = JSON.parse(data);
    } catch(e) {
      return;
    }
    if (parsed.reload) {
     location.reload();
    }
    if (parsed.reload_state) {
     var state = $("#auth_status").html();
     if (state && state != parsed.reload_state) {
      location.reload();
     }
    }
    if (parsed.alert) {
     alert(parsed.alert);
    }
 });
});
