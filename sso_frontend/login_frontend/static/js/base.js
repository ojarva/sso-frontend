function login_ping() {
 $.get("/ping/internal/js?"+ document.location.search, function(data) {
  if ("redirect_location" in data) {
   document.location.href=data.redirect_location;
  }
 });

 setTimeout(login_ping, 300000);
}

function refresh_timestamps() {
 $("time.timeago").each(function() {
  $(this).html(moment($(this).attr("datetime")).fromNow());
 });

 $("span.onlybefore").each(function() {
  valid_until = $(this).data("timestamp");
  if (moment(valid_until) < moment()) {
   $(this).addClass("hidden");
   $(this).removeClass("onlybefore");
  }
 });

 $("span.onlyafter").each(function() {
  valid_until = $(this).data("timestamp");
  if (moment(valid_until) < moment()) {
   $(this).removeClass("hidden");
   $(this).removeClass("onlyafter");
  }
 });
}

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$.ajaxSetup({
    crossDomain: false, // obviates need for sameOrigin test
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type)) {
            csrftoken = $("#csrf_token").html();
            if (csrftoken) {
             xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    }
});


$(document).ready(function() {
 stick.send('/services/timing/record');
 refresh_timestamps();
 setInterval(refresh_timestamps, 3000);
 $(".popover-link").popover();
 $(".tooltip-link").tooltip();
 $(".autofocus").focus();
 $(".autoselect").focus(function() {$(this).select();});
 $(".autosubmit").submit();
 $(".toggle").click(function() {
  var destination_class = $("."+ $(this).data("open-class"));
  $(destination_class).toggleClass("hidden");
 });
// setTimeout(login_ping, 300000);
 $(".track_content").timing({"destination": "#timing_data"});
});
