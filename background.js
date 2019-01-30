function trigger_tab(){
	browser.tabs.create({url: "/main.html"});
}

browser.browserAction.onClicked.addListener(trigger_tab);
