var app = require('http').createServer(handler)
  , io = require('socket.io').listen(app)
  , fs = require('fs')
var redis = require('redis');
var pub = redis.createClient();
var sub = redis.createClient();
  var StatsD = require('node-statsd').StatsD,
      sd = new StatsD();

var sockets = [];
var pubsubs = [];
var pubsub_channels = [];

function handler() {}

app.listen(3033);

io.sockets.on('connection', function (socket) {
  sd.increment("websockets.connection");
  socket.on("authenticate", function (data) {
    sd.increment("websockets.authenticate");
    var pubsub_key = "to-browser-"+data.bid_public;
    var pubsub_dedup_key = "to-browser-"+data.bid_public+"-tab-"+data.tab_id;
    var i = pubsub_channels.indexOf(pubsub_dedup_key);
    if (i >= 0) {
       console.log("Already registered", pubsub_dedup_key);
    }
    const subscribe = redis.createClient();
    pubsubs.push(subscribe);
    pubsub_channels.push(pubsub_key);
    sockets.push(socket);
    subscribe.subscribe(pubsub_key);
    console.log("subscribing to", pubsub_key);
    subscribe.on("message", function(channel, message, pattern) {
      console.log("Received raw:", message);
      sd.increment("websockets.emit");
      console.log("Sending", message);
      socket.emit("server_event", message);
    });
  });

  socket.on('browser_event', function (data) {
    sd.increment("websockets.receive");
    console.log(data);
  });

  socket.on("disconnect", function() {
    sd.increment("websockets.disconnect");
    var i = sockets.indexOf(socket);
    if (i >= 0) {
      sd.increment("websockets.unsubscribe");
      console.log("unsubscribing", i);
      pubsubs[i].unsubscribe();
      pubsubs[i].end();
      pubsubs.splice(i, 1);
      pubsub_channels.splice(i, 1);
      sockets.splice(i, 1);
    }
  });
  socket.on("active", function(data) {
  });
});
