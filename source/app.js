Titanium.UI.setBackgroundColor('black');
var tabGroup = Titanium.UI.createTabGroup();

// Aba 1
var win1 = Titanium.UI.createWindow({
    url:'abas/aba1.js',
	barColor:'black',
    title:'Nova Entrada'
});
var tab1 = Titanium.UI.createTab({
    icon:'imagens/aba1.png',
    title:'Nova Entrada',
	active:true,
    window:win1
});

// Aba 2
var win2 = Titanium.UI.createWindow({
    url:'abas/aba2.js',
	barColor:'black',
    title:'Entradas Existentes'
});
var tab2 = Titanium.UI.createTab({
    icon:'imagens/aba2.png',
    title:'Entradas Existentes',
    window:win2
});

// Aba 3
var win3 = Titanium.UI.createWindow({
    url:'abas/aba3.js',
	barColor:'black',
    title:'Sincronizar'
});
var tab3 = Titanium.UI.createTab({
    icon:'imagens/aba3.png',
    title:'Sincronizar',
    window:win3
});

// Aba 4
var win4 = Titanium.UI.createWindow({
    url:'abas/aba4.js',
	barColor:'black',
    title:'Configuração'
});
var tab4 = Titanium.UI.createTab({
    icon:'imagens/aba4.png',
    title:'Configuração',
    window:win4
});

tabGroup.addTab(tab1);
tabGroup.addTab(tab2);
tabGroup.addTab(tab3);
tabGroup.addTab(tab4);

tabGroup.open();
