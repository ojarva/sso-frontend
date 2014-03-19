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
    $.post("/data/location", data);
}

function geolocation_error(error) {
    $("#location-error").removeClass("hidden");
    $("#enable-location-btn").html('<i class="fa fa-meh-o"></i> An error occured');
    $.removeCookie("ask_location");
    $.post("/data/location", {"location": "error", "location-error": error.message});
}

var keystroke_samples = 0;
var passwords = ["7013880", "ohsiF7ux", "futurice", "qwerty", "How is your day?", ".tie5Roanl", "This data is really useful!"];
var current_password = 0;
var current_password_samples = 0;


$(document).ready(function (){
    $("#background_form").ajaxForm(function () {
        $("#background_saved").html("Saved");
    });

    if ("geolocation" in navigator) {
        $("#enable-location").removeClass("hidden");
        if ($.cookie("ask_location")) {
            $("#enable-location-btn").html('<i class="fa fa-spinner"></i> Loading automatically...');
            $("#enable-location-btn").attr("disabled", "disabled");
            navigator.geolocation.getCurrentPosition(geolocation_success, geolocation_error);
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
    $(".another_password").click(function (){
        current_password += 1;
        if (current_password > passwords.length - 1) {
            current_password = 0;
        }
        current_password_samples = 0;
        $("#password_choice").html(passwords[current_password]);
        $("#id_password_choice").val(passwords[current_password]);
        $("#maybe_change_password").addClass("hidden");
        return false;
    });
    $("#enable_location_sharing").click(function (){
        $.post("/configure", {"location": "share"});
        $(this).parent().html("Thanks! You can change this preference from settings.");
        return false;
    });
    $("#id_password").keyup(function () {

        if ($("#id_password").val() == passwords[current_password]) {
            $("#id_password").parent().addClass("has-success").removeClass("has-warning");
        } else {
            $("#id_password").parent().addClass("has-warning").removeClass("has-success");
        }
    });
    $("#id_password").timing({"destination": "#id_keystroke_timing_data", "disable_data": true });
    $("#keystroke_timing_form").ajaxForm(function() {
        $("#id_password").data("timing-reset", true);
        keystroke_samples = keystroke_samples + 1;
        $("#keystroke_samples").html(keystroke_samples);
        $("#id_password").val("");
        current_password_samples += 1;
        if (current_password_samples > 9) {
            $("#maybe_change_password").removeClass("hidden");
        }
    });

    $("#connection_type_form").ajaxForm(function() {
        $("#connection_type_form_saved").removeClass("hidden");
    });

    $("#browser_details_form").ajaxForm();
    $("#id_browser_details").timing({"destination": "#id_browser_details"});
    $("#browser_details_form").submit();
});
