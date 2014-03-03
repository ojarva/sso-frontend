function get_time() {
 return (new Date()).getTime();
}

$(document).ready(function() {
 var random_id = Math.floor(Math.random() * 100000000);
 var tz_off = date.getTimezoneOffset()

 send_timestamp = get_time()
 $.get("/timesync/"+random_id+"/"+tz_off+"/"+ send_timestamp, function(data) {
  send_timestamp = get_time()
  $.get("/timesync/"+random_id+"/"+tz_off+"/"+ send_timestamp + "/" + data.server_time, function(data) {
   send_timestamp = get_time()
   $.get("/timesync/"+random_id+"/"+tz_off+"/"+ send_timestamp + "/" + data.server_time, function(data) {
    send_timestamp = get_time()
    $.get("/timesync/"+random_id+"/"+tz_off+"/"+ send_timestamp + "/" + data.server_time, function(data) {
     send_timestamp = get_time()
     $.get("/timesync/"+random_id+"/"+tz_off+"/"+ send_timestamp + "/" + data.server_time+"/results", function(data) {
      $("#timesync_report").html(data.report);
     });
    });
   });
  });
 });
});
