(function( $ ) {

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

    function count_password_strength(password) {
        strength = {"number": 0, "lowercase": 0, "uppercase": 0, "other": 0, "space": 0};
        for (i = 0; i < password.length; i++) {
            var c = (password.charCodeAt(i));
            if (c >= 48 && c <= 57) {
                strength.number++;
            } else if ((c >= 65 && c <= 90) || c == 196 || c == 214 || c == 197) {
                strength.uppercase++;
            } else if ((c >= 97 && c <= 122) || c == 228 || c == 246 || c == 229) {
                strength.lowercase++;
            } else if (c == 32) {
                strength.space++;
            } else {
                strength.other++;
            }
        }
        return strength;
    }

    function handle_key_event(item, event_code, e, options) {
        var data = $(options.destination).data("timing");
        var id = item.attr("id");
        if (item.data("timing-reset")) {
            data[id].timing = [];
            item.removeData("timing-reset")
        }

        var keycode = e.keyCode || "";
        var timestamp = e.timeStamp || 0;

        var d = {"a": event_code, "k": "", "t": timestamp, "r_t": (new Date()).getTime(), "l": item.val().length }
        if (keycode < 48 || keycode > 90) {
            d.k = keycode;
        } else {
            d.k = "add";
        }
        data[id].timing.push(d)

        var s = item.val();
        data[id].strength = count_password_strength(s);
        $(options.destination).data("timing", data);
        $(options.destination).val(JSON.stringify(data));
    }

    $.fn.timing = function(options) {
        var data = {};
        try {
            data.resolution = window.screen;
        } catch (e) {
        }
        if (options.disable_data !== true) {
            try {
                data.performance = get_performance_data();
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
        }

        date = new Date();
        data.browserclock = {"timezoneoffset": date.getTimezoneOffset(), "utciso": date.toISOString() };
        $(options.destination).data("timing", data);
        $(options.destination).val(JSON.stringify(data));

        return this.each(function () {
            var id = $(this).attr("id");
            data[id] = {"timing": [], "strength": false};
            $(options.destination).data("timing", data);

            $(this).keyup(function(e) {
                var item = $(this);
                handle_key_event(item, "keyup", e, options);
            });

            $(this).keydown(function(e) {
                handle_key_event($(this), "keydown", e, options);
            });

            $(this).keypress(function(e) {
                handle_key_event($(this), "keypress", e, options);
            });
        });


    }

}) (jQuery);
