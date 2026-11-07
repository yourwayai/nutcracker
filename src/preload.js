const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nutcracker', {
  vault: {
    exists:         ()                    => ipcRenderer.invoke('vault:exists'),
    create:         (pw)                  => ipcRenderer.invoke('vault:create', pw),
    unlock:         (pw)                  => ipcRenderer.invoke('vault:unlock', pw),
    save:           (pw, data)            => ipcRenderer.invoke('vault:save', pw, data),
    changePassword: (oldPw, newPw)        => ipcRenderer.invoke('vault:changePassword', oldPw, newPw),
    export:         (pw)                  => ipcRenderer.invoke('vault:export', pw),
  },
  app: {
    getVaultPath: () => ipcRenderer.invoke('app:getVaultPath'),
  },
});
