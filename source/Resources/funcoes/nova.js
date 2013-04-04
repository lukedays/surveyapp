var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, Titanium.App.Properties.getString('nome'));
var arquivo = JSON.parse(f.read().text);

var x = 1;
while (arquivo.registros[x] != null) {
	x++;
}
arquivo.registros[x] = [];

Titanium.include('includes.js');
Titanium.include('main.js');