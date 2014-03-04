function get_time() {
 return (new Date()).getTime();
}

function ping_roundtrip(random_id, tz_off, counter, data) {
 counter = counter - 1;
 var send_timestamp = get_time();
 var results = false;
 var url = "/timesync/"+random_id+"/"+tz_off+"/"+send_timestamp;
 if (data) {
  url += "/"+data.server_time;
 }
 if (counter < 1) {
  url += "/results";
  results = true;
 }
 $.ajax({
   "url": url,
   "error": function(jqxhr, textstatus, errorthrown) {
    $("#timesync_report").html("An error occured: "+errorthrown);
   }
 }).done(function(data) {
  if (results) {
   $("#timesync_report").html(data.report);
  } else {
   ping_roundtrip(random_id, tz_off, counter, data);
  }
 });
}

$(document).ready(function() {
 var random_id = Math.floor(Math.random() * 100000000);
 var tz_off = date.getTimezoneOffset()

 ping_roundtrip(random_id, tz_off, 5);
});
