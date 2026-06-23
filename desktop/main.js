const { app, BrowserWindow, Menu, Tray } = require('electron');
const path = require('path');

const DASHBOARD_URL = process.env.SNAPESCAPE_URL || 'http://localhost:3000';

function createWindow() {
  const win = new BrowserWindow({
    width: 1600, height: 1000,
    title: 'SNAPESCAPE — Attack Surface Intelligence',
    backgroundColor: '#0a0a12',
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });
  win.loadURL(DASHBOARD_URL);
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'SNAPESCAPE', submenu: [
      { label: 'Reload', click: () => win.reload() },
      { label: 'DevTools', click: () => win.webContents.openDevTools() },
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() },
    ]},
    { label: 'Scan', submenu: [
      { label: 'New Scan', accelerator: 'CmdOrCtrl+N', click: () => win.webContents.executeJavaScript('document.querySelector("input")?.focus()') },
    ]},
  ]));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
