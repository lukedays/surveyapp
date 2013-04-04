var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, Titanium.App.Properties.getString('nome'));
var arquivo = JSON.parse(f.read().text);

var x = Titanium.App.Properties.getInt('x');

Titanium.include('includes.js');
Titanium.include('main.js');