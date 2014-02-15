function login_ping() {
 $.get("/v2/ping/internal/js?"+ document.location.search, function(data) {
  if ("redirect_location" in data) {
   document.location.href=data.redirect_location;
  }
 });

 setTimeout(login_ping, 30000);
}

$(document).ready(function() {
 $(".popover-link").popover();
 $(".tooltip-link").tooltip();
 $(".autofocus").focus();
 $(".autoselect").focus(function() {$(this).select();});
 $(".toggle").click(function() {
  var destination_class = $("."+ $(this).data("open-class"));
  $(destination_class).toggleClass("hidden");
 });
 setTimeout(login_ping, 30000);

});
