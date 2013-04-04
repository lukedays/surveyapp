Titanium.include('../funcoes/includes.js');

inc_instalacao();

var tableView;

inc_abrir('../funcoes/nova.js');

var atualizar = Titanium.UI.createButton({
	title:'Atualizar',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});

atualizar.addEventListener('click', function(e)
{
	inc_abrir('../funcoes/nova.js');
	
	Titanium.UI.currentWindow.animate({view:tableView, transition:Ti.UI.iPhone.AnimationStyle.CURL_DOWN});
	Titanium.UI.currentWindow.setToolbar([atualizar]);
	Titanium.UI.currentWindow.add(tableView);
});

Titanium.UI.currentWindow.setToolbar([atualizar]);
Titanium.UI.currentWindow.add(tableView);