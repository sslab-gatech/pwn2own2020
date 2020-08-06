print = function(msg) {
  var logs = document.getElementById('logs');
  var t = document.createTextNode(msg);
  logs.appendChild(t);
  var br = document.createElement('br');
  logs.appendChild(br);
}
