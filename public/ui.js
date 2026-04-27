const ui = {
    _modal: null,
    _resolve: null,
    _toastContainer: null,

    init() {
        if (this._modal) return;

        // Create Modal Structure
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-container">
                <div class="modal-header">
                    <span class="modal-title" id="modal-title"></span>
                </div>
                <div class="modal-content" id="modal-content"></div>
                <div class="modal-footer" id="modal-footer"></div>
            </div>
        `;
        document.body.appendChild(overlay);
        this._modal = overlay;

        // Create Toast Container
        const tc = document.createElement('div');
        tc.className = 'toast-container';
        document.body.appendChild(tc);
        this._toastContainer = tc;
    },

    showModal({ title, content, actions }) {
        this.init();
        document.getElementById('modal-title').textContent = title;
        const contentEl = document.getElementById('modal-content');

        if (typeof content === 'string') {
            contentEl.innerHTML = content;
        } else {
            contentEl.innerHTML = '';
            contentEl.appendChild(content);
        }

        const footer = document.getElementById('modal-footer');
        footer.innerHTML = '';
        actions.forEach(action => {
            const btn = document.createElement('button');
            btn.className = `btn ${action.className || 'btn-secondary'}`;
            btn.textContent = action.label;
            btn.onclick = () => {
                if (action.onClick) {
                    const result = action.onClick();
                    if (result === false) return;
                }
                this.closeModal();
            };
            footer.appendChild(btn);
        });

        this._modal.classList.add('show');
    },

    closeModal() {
        if (this._modal) {
            this._modal.classList.remove('show');
        }
    },

    alert(message, title = 'Alert') {
        return new Promise(resolve => {
            this.showModal({
                title,
                content: `<p style="font-size: 14px; color: var(--text-secondary);">${message}</p>`,
                actions: [{ label: 'OK', className: 'btn-primary', onClick: resolve }]
            });
        });
    },

    confirm(message, title = 'Confirm') {
        return new Promise(resolve => {
            this.showModal({
                title,
                content: `<p style="font-size: 14px; color: var(--text-secondary);">${message}</p>`,
                actions: [
                    { label: 'Cancel', className: 'btn-ghost', onClick: () => resolve(false) },
                    { label: 'Confirm', className: 'btn-primary', onClick: () => resolve(true) }
                ]
            });
        });
    },

    prompt(fields, title = 'Input') {
        return new Promise(resolve => {
            const container = document.createElement('div');
            container.style.display = 'flex';
            container.style.flexDirection = 'column';
            container.style.gap = '12px';
            const inputs = {};

            fields.forEach(f => {
                const group = document.createElement('div');
                group.style.display = 'flex';
                group.style.flexDirection = 'column';
                group.style.gap = '4px';

                const inputId = 'prompt-' + f.name;
                const label = document.createElement('label');
                label.textContent = f.label;
                label.setAttribute('for', inputId);
                label.style.fontSize = '11px';
                label.style.color = 'var(--text-muted)';
                label.style.textTransform = 'uppercase';
                group.appendChild(label);

                const input = document.createElement('input');
                input.id = inputId;
                input.className = 'input';
                input.type = f.type || 'text';
                input.value = f.value || '';
                input.placeholder = f.placeholder || '';
                group.appendChild(input);
                container.appendChild(group);
                inputs[f.name] = input;
            });

            this.showModal({
                title,
                content: container,
                actions: [
                    { label: 'Cancel', className: 'btn-ghost', onClick: () => resolve(null) },
                    {
                        label: 'Submit',
                        className: 'btn-primary',
                        onClick: () => {
                            const values = {};
                            Object.entries(inputs).forEach(([k, v]) => values[k] = v.value);
                            resolve(values);
                        }
                    }
                ]
            });
        });
    },

    showToast(message, type = 'info') {
        this.init();
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        this._toastContainer.appendChild(toast);

        requestAnimationFrame(() => {
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(20px)';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        });
    }
};

window.ui = ui;
