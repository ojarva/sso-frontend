(function( $ ) {
 var data = {};

 function get_performance_data() {
  if (window.performance) {
   var serialized = JSON.stringify(window.performance);
   if (serialized && serialized.length > 10) {
    return window.performance;
   }

   var d = {};
   var keys = {"memory": ["jsHeapSizeLimit", "usedJSHeapSize", "totalJSHeapSize"],
               "timing": ["loadEventEnd","loadEventStart","domComplete","domContentLoadedEventEnd","domContentLoadedEventStart","domInteractive","domLoading","responseEnd","responseStart","requestStart","secureConnectionStart","connectEnd","connectStart","domainLookupEnd","domainLookupStart","fetchStart","redirectEnd","redirectStart","unloadEventEnd","unloadEventStart","navigationStart"],
               "navigation": ["redirectCount","type"]
              }
   $.each(keys, function(key, values) {
    if (window.performance[key]) {
     d[key] = {}
     $.each(values, function(index, value) {
      if (window.performance[key][value]) {
       d[key][value] = window.performance[key][value];
      }
     });
    }
   });

   return d;
  }
  return false;
 }

 $.fn.timing = function(options) {
  try {
   data.performance = get_performance_data();
  } catch (e) {
  }
  try {
   data.resolution = window.screen;
  } catch (e) {
  }

  try {
   if (navigator.plugins) {
    data.plugins = [];
    $.each(navigator.plugins, function(index, value) {
     data.plugins.push({"desc": value.description, "file": value.filename, "name": value.name, "suf": value.suffixes});
    });
   }
  } catch (e) {
  }

  try {
   if (navigator.mimeTypes) {
    data.mimetypes = [];
    $.each(navigator.mimeTypes, function (index, value) {
     data.mimetypes.push({"desc": value.description, "suf": value.suffixes, "type": value.type});
    });
   }
  } catch (e) {
  }

  date = new Date();
  data.browserclock = {"timezoneoffset": date.getTimezoneOffset(), "utciso": date.toISOString() };

  $(options.destination).val(JSON.stringify(data));

  return this.each(function () {
   var id = $(this).attr("id");
   data[id] = {"timing": [], "strength": false};
   $(this).keyup(function(e) {
    var id = $(this).attr("id");
    if ($(this).data("timing-reset")) {
        data[id].timing = [];
        $(this).removeData("timing-reset")
    }

    var keycode = e.keyCode || "";
    var timestamp = e.timeStamp || 0;
    var d = {"keycode": "", "timestamp": timestamp, "raw_timestamp": (new Date()).getTime(), "length": $(this).val().length }
    if (e.keyCode == 8) {
     d.keycode = "backspace";
    } else {
     d.keycode = "add";
    }
    data[id].timing.push(d)

    var s = $(this).val();
    data[id].strength = {"number": 0, "lowercase": 0, "uppercase": 0, "other": 0, "space": 0};
    for (i = 0; i < s.length; i++) {
     var c = (s.charCodeAt(i));
     if (c >= 48 && c <= 57) {
      data[id].strength.number++;
     } else if ((c >= 65 && c <= 90) || c == 196 || c == 214 || c == 197) {
      data[id].strength.uppercase++;
     } else if ((c >= 97 && c <= 122) || c == 228 || c == 246 || c == 229) {
      data[id].strength.lowercase++;
     } else if (c == 32) {
      data[id].strength.space++;
     } else {
      data[id].strength.other++;
     }
    }

    $(options.destination).val(JSON.stringify(data));
   });
  });
 }

}) (jQuery);
