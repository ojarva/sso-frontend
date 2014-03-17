function check_notifications() {
 if (window.webkitNotifications.checkPermission() == 0) {
  $("#enable-notification").addClass("hidden");
  $("#enable-notification-thanks").removeClass("hidden");
 } else {
  setInterval(check_notifications, 1000);
 }
}

function geolocation_success(coords) {
 $("#enable-location").addClass("hidden");
 $("#enable-location-thanks").removeClass("hidden");
 $.post("?", {"location": "share"});
 data = {}
 c = coords.coords;
 data["latitude"] = c.latitude;
 data["longitude"] = c.longitude;
 data["accuracy"] = c.accuracy;
 data["altitude"] = c.altitude;
 data["altitude_accuracy"] = c.altitudeAccuracy;
 data["speed"] = c.speed;
 data["heading"] = c.heading;
 $.post("/ping/location", data);
}

function geolocation_error(error) {
 $("#location-error").removeClass("hidden");
 $("#enable-location-btn").html('<i class="fa fa-meh-o"></i> An error occured');
 $.post("?", {"location": "error", "location-error": error.message});
}

$(document).ready(function() {
 if (window.webkitNotifications) {
  if (window.webkitNotifications.checkPermission() != 0) {
   $("#enable-notification").removeClass("hidden");
   $("#enable-notification-btn").click(function () {
    window.webkitNotifications.requestPermission();
    check_notifications();
   });
  }
 }

 if (navigator.geolocation) {
  $("#enable-location").removeClass("hidden");
  $("#enable-location-btn").click(function () {
   $("#enable-location-btn").html('<i class="fa fa-spinner"></i> Loading...');
   $("#enable-location-btn").attr("disabled", "disabled");
   navigator.geolocation.getCurrentPosition(geolocation_success, geolocation_error);
  });
 }
});
