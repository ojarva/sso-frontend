function handle_location(coords) {
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
function handle_location_error(err) {
 console.log(err);
}

$(document).ready(function() {
 if ("geolocation" in navigator) {
  navigator.geolocation.getCurrentPosition(handle_location, handle_location_error);
 }
});
