function geolocation_success(coords) {
    $("#enable-location").addClass("hidden");
    $("#enable-location-thanks").removeClass("hidden");
    data = {}
    c = coords.coords;
    data["latitude"] = c.latitude;
    data["longitude"] = c.longitude;
    data["accuracy"] = c.accuracy;
    data["altitude"] = c.altitude;
    data["altitude_accuracy"] = c.altitudeAccuracy;
    data["speed"] = c.speed;
    data["heading"] = c.heading;
    $.post("/data/location_only", data, function (response_data) {
        $("#location-geoip").html(response_data);
    });
}

function geolocation_error(error) {
    $("#location-error").removeClass("hidden");
    $("#enable-location-btn").html('<i class="fa fa-meh-o"></i> An error occured');
    $.post("/data/location", {"location": "error", "location-error": error.message, "location-code": error.code});
    if (error.code == 1) {
        $("#location-error-message").html("You denied access to geolocation. You can't finish this task without sharing your location.");
    } else if (error.code == 2) {
        $("#location-error-message").html("Your browser is unable to locate you. You can't finish this task without a device that can do it. If you're using laptop, try turning on wifi and refreshing this page.");
        if (error.message) {
            $("#location-error-extra").html("Your browser reported '"+error.message+"' as error message.");
        }
    }
}

$(document).ready(function (){
    if ("geolocation" in navigator) {
        $("#enable-location").removeClass("hidden");
        if ($.cookie("ask_location")) {
            $("#enable-location-btn").html('<i class="fa fa-spinner"></i> Loading automatically...');
            $("#enable-location-btn").attr("disabled", "disabled");
            navigator.geolocation.getCurrentPosition(geolocation_success, geolocation_error, {maximumAge: 120000});
        }
        $("#enable-location-btn").click(function () {
         $("#enable-location-btn").html('<i class="fa fa-spinner"></i> Loading...');
         $("#enable-location-btn").attr("disabled", "disabled");
         navigator.geolocation.getCurrentPosition(geolocation_success, geolocation_error);
        });
    } else {
        $("#no_location_available").removeClass("hidden");
        $("#share_location_span").addClass("hidden");
        $("#enable-location").addClass("hidden");
    }

    $("#browser_details_form").ajaxForm();
    $("#id_browser_details").timing({"destination": "#id_browser_details"});
    $("#browser_details_form").submit();
});
