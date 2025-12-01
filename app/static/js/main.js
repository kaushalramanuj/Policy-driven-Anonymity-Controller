/**
 * Policy-Driven Anonymity Controller
 * Main JavaScript Module
 */

// ============================================
// Utility Functions
// ============================================

/**
 * Toggle accordion sections
 * @param {HTMLElement} header - The accordion header element that was clicked
 */
function toggleAccordion(header) {
    const item = header.parentElement;
    const body = header.nextElementSibling;
    const icon = header.querySelector('.toggle-icon');
    
    if (!item || !body) return;
    
    const isActive = item.classList.contains('active');
    
    if (isActive) {
        // Close the accordion
        item.classList.remove('active');
        body.style.display = 'none';
        if (icon) {
            icon.style.transform = 'rotate(0deg)';
        }
    } else {
        // Open the accordion
        item.classList.add('active');
        body.style.display = 'block';
        if (icon) {
            icon.style.transform = 'rotate(180deg)';
        }
    }
}

// Make toggleAccordion available globally
window.toggleAccordion = toggleAccordion;

// ============================================
// Theme Management
// ============================================

const ThemeManager = {
    init() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        this.setTheme(savedTheme);
        this.bindEvents();
    },

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        this.updateToggleButton(theme);
    },

    toggle() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    },

    updateToggleButton(theme) {
        const icon = document.querySelector('.theme-toggle i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    },

    bindEvents() {
        const toggleBtn = document.querySelector('.theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggle());
        }
    }
};

// ============================================
// Toast Notifications
// ============================================

const Toast = {
    container: null,

    init() {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        this.container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(this.container);
    },

    show(message, type = 'info', duration = 4000) {
        if (!this.container) this.init();

        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;
        toast.style.cssText = `
            padding: 1rem 1.5rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            min-width: 300px;
            max-width: 450px;
            animation: slideInRight 0.3s ease, fadeOut 0.3s ease ${duration - 300}ms forwards;
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        `;

        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        const colors = {
            success: 'var(--success)',
            error: 'var(--danger)',
            warning: 'var(--warning)',
            info: 'var(--info)'
        };

        toast.style.background = 'var(--bg-card)';
        toast.innerHTML = `
            <i class="fas ${icons[type]}" style="color: ${colors[type]}; font-size: 1.25rem;"></i>
            <span style="color: var(--text-primary); flex: 1;">${message}</span>
            <button class="toast-close" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.25rem;">
                <i class="fas fa-times"></i>
            </button>
        `;

        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.style.animation = 'fadeOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        });

        this.container.appendChild(toast);
        setTimeout(() => toast.remove(), duration);
    },

    success(message) { this.show(message, 'success'); },
    error(message) { this.show(message, 'error', 6000); },
    warning(message) { this.show(message, 'warning'); },
    info(message) { this.show(message, 'info'); }
};

// Add animation styles
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    @keyframes fadeOut {
        to { opacity: 0; transform: translateX(100px); }
    }
`;
document.head.appendChild(toastStyles);

// ============================================
// API Client
// ============================================

const API = {
    async request(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const config = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(endpoint, config);
            const data = await response.json();
            
            // Log the parsed JSON data, not the Response object
            console.log(`API Response [${endpoint}]:`, data);
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    get(endpoint) {
        return this.request(endpoint);
    },

    post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
};

// ============================================
// System Status Manager
// ============================================

const SystemStatus = {
    updateInterval: null,

    async load() {
        try {
            const data = await API.get('/system-status');
            this.update(data);
            return data;
        } catch (error) {
            console.error('Failed to load system status:', error);
            this.setOffline();
        }
    },

    update(data) {
        console.log('Updating system status with data:', data);
        
        // Handle the actual API response structure
        const proxyManager = data.proxy_manager || {};
        const backends = proxyManager.backends || {};
        const torConnectivity = data.tor_connectivity || {};
        const policyEngine = data.policy_engine || {};
        const fingerprintManager = data.fingerprint_manager || {};
        
        // Update Policy Engine - check multiple possible fields
        const policyActive = policyEngine.active || policyEngine.status === 'active' || policyEngine.healthy;
        this.updateStatus('policy-engine', policyActive, policyActive ? 'Active' : 'Inactive');
        
        // Update Proxy Manager - it's active if we have the proxy_manager.active flag
        const proxyActive = proxyManager.active === true;
        this.updateStatus('proxy-manager', proxyActive, proxyActive ? 'Available' : 'Unavailable');
        
        // Update Tor Network - check tor_connectivity first, then backends.tor.working
        const torConnected = torConnectivity.connected || 
                           torConnectivity.is_tor || 
                           backends.tor?.working === true;
        this.updateStatus('tor-network', torConnected, torConnected ? 'Connected' : 'Disconnected');
        
        // Update Fingerprint Protection
        const fpEnabled = fingerprintManager.protection_enabled !== false;
        this.updateStatus('fingerprint', fpEnabled, fpEnabled ? 'Ready' : 'Disabled');
        
        // Update backend counts if elements exist
        this.updateCount('tor-count', torConnected ? 1 : 0);
        this.updateCount('https-count', 0);
        this.updateCount('http-count', 0);
        
        // Log for debugging
        console.log('Status update results:', {
            policyActive,
            proxyActive,
            torConnected,
            fpEnabled
        });
    },

    updateStatus(id, isOnline, text) {
        const statusIcon = document.getElementById(`${id}-icon`);
        const statusDot = document.getElementById(`${id}-dot`);
        const statusText = document.getElementById(`${id}-text`);

        if (statusIcon) {
            statusIcon.className = statusIcon.className.replace(/online|offline|warning/g, '').trim();
            statusIcon.classList.add(isOnline ? 'online' : 'offline');
        }

        if (statusDot) {
            statusDot.className = 'status-dot ' + (isOnline ? 'online' : 'offline');
        }

        if (statusText) {
            statusText.textContent = text;
            statusText.className = isOnline ? 'text-success' : 'text-danger';
        }
    },

    updateCount(id, count) {
        const element = document.getElementById(id);
        if (element) {
            this.animateNumber(element, parseInt(element.textContent) || 0, count);
        }
    },

    animateNumber(element, from, to) {
        const duration = 500;
        const start = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - start;
            const progress = Math.min(elapsed / duration, 1);
            const value = Math.round(from + (to - from) * this.easeOutQuad(progress));
            element.textContent = value;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    },

    easeOutQuad(t) {
        return t * (2 - t);
    },

    setOffline() {
        ['policy-engine', 'proxy-manager', 'tor-network', 'fingerprint'].forEach(id => {
            this.updateStatus(id, false, 'Offline');
        });
    },

    startAutoRefresh(interval = 30000) {
        this.load();
        this.updateInterval = setInterval(() => this.load(), interval);
    },

    stopAutoRefresh() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
};

// ============================================
// User Statistics Manager
// ============================================

const UserStats = {
    async load() {
        try {
            const data = await API.get('/user-stats');
            this.update(data);
            return data;
        } catch (error) {
            console.error('Failed to load user stats:', error);
            this.showError();
        }
    },

    update(data) {
        const container = document.getElementById('user-stats');
        if (!container) return;

        if (data.message) {
            container.innerHTML = `
                <div class="text-center" style="color: var(--text-muted); padding: 2rem;">
                    <i class="fas fa-chart-bar" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                    <p>${data.message}</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="stats-grid">
                <div class="mini-stat">
                    <span class="mini-stat-value text-gradient">${data.total_requests}</span>
                    <span class="mini-stat-label">Total Requests</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-stat-value text-gradient">${data.success_rate?.toFixed(1) || 0}%</span>
                    <span class="mini-stat-label">Success Rate</span>
                </div>
            </div>
            <div class="stats-detail mt-2">
                <div class="d-flex justify-between align-center" style="padding: 0.75rem; background: var(--bg-glass); border-radius: var(--radius-sm);">
                    <span style="color: var(--text-muted);">Avg Response Time</span>
                    <span style="font-weight: 600;">${data.average_response_time?.toFixed(2) || 0}s</span>
                </div>
            </div>
        `;
    },

    showError() {
        const container = document.getElementById('user-stats');
        if (container) {
            container.innerHTML = `
                <div class="alert-custom alert-danger-custom">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>Failed to load statistics</span>
                </div>
            `;
        }
    }
};

// ============================================
// Anonymity Request Handler
// ============================================

const AnonymityRequest = {
    form: null,
    submitBtn: null,

    init() {
        this.form = document.getElementById('anonymity-form');
        this.submitBtn = this.form?.querySelector('button[type="submit"]');
        
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
            this.bindMethodChange();
        }
    },

    bindMethodChange() {
        const methodSelect = document.getElementById('method');
        const postDataSection = document.getElementById('post-data-section');
        
        if (methodSelect && postDataSection) {
            methodSelect.addEventListener('change', () => {
                const showData = ['POST', 'PUT', 'PATCH'].includes(methodSelect.value);
                postDataSection.style.display = showData ? 'block' : 'none';
            });
        }
    },

    async handleSubmit(e) {
        e.preventDefault();
        
        const targetUrl = document.getElementById('target-url').value;
        const method = document.getElementById('method').value;
        const backend = document.getElementById('backend').value;
        const fingerprintProtection = document.getElementById('fingerprint-protection')?.checked ?? true;
        
        // Validate URL
        if (!targetUrl) {
            Toast.error('Please enter a target URL');
            return;
        }

        try {
            new URL(targetUrl);
        } catch {
            Toast.error('Please enter a valid URL');
            return;
        }

        // Prepare request data
        const requestData = {
            target_url: targetUrl,
            method: method,
            backend_preference: backend,
            fingerprint_protection: fingerprintProtection
        };

        // Add POST data if applicable
        if (['POST', 'PUT', 'PATCH'].includes(method)) {
            const postData = document.getElementById('post-data')?.value?.trim();
            if (postData) {
                try {
                    requestData.data = JSON.parse(postData);
                } catch {
                    Toast.error('Invalid JSON in request data');
                    return;
                }
            }
        }

        this.setLoading(true);
        Toast.info('Processing your anonymous request...');

        try {
            const result = await API.post('/make-request', requestData);
            this.displayResults(result);
            UserStats.load(); // Refresh stats
            
            if (result.success) {
                Toast.success('Request completed successfully!');
            } else {
                Toast.error(result.error || 'Request failed');
            }
        } catch (error) {
            this.displayResults({ success: false, error: error.message });
            Toast.error(error.message || 'Request failed');
        } finally {
            this.setLoading(false);
        }
    },

    setLoading(isLoading) {
        if (!this.submitBtn) return;
        
        const btnText = this.submitBtn.querySelector('.btn-text');
        const spinner = this.submitBtn.querySelector('.spinner');
        
        this.submitBtn.disabled = isLoading;
        
        if (btnText) {
            btnText.textContent = isLoading ? 'Processing...' : 'Send Anonymous Request';
        }
        
        if (spinner) {
            spinner.style.display = isLoading ? 'inline-block' : 'none';
        }
    },

    displayResults(response) {
        const resultsCard = document.getElementById('results-card');
        const resultsDiv = document.getElementById('request-results');
        
        if (!resultsCard || !resultsDiv) return;

        console.log('Display Results - Full Response:', response);

        if (response.success) {
            // Handle nested performance object
            const responseTime = response.performance?.total_time 
                ?? response.performance?.execution_time 
                ?? response.total_time 
                ?? response.response_time 
                ?? response.time;
            
            const timeDisplay = (responseTime !== undefined && responseTime !== null) 
                ? `${parseFloat(responseTime).toFixed(2)}s` 
                : 'N/A';

            // Extract page metadata from HTML content
            const pageMetadata = this.extractPageMetadata(response.response?.content);

            resultsDiv.innerHTML = `
                <div class="alert-custom alert-success-custom mb-3">
                    <i class="fas fa-check-circle"></i>
                    <div>
                        <strong>Request Successful!</strong>
                        <div class="mt-1" style="font-size: 0.9rem;">
                            Backend: <span class="badge-custom badge-info">${response.backend_used || response.backend || 'N/A'}</span>
                            Time: <span class="badge-custom badge-success">${timeDisplay}</span>
                            ${response.fingerprint_protection ? '<span class="badge-custom badge-warning">FP Protected</span>' : ''}
                        </div>
                    </div>
                </div>

                <div class="accordion-custom">
                    <!-- Page Preview Section -->
                    <div class="accordion-item-custom active">
                        <div class="accordion-header-custom" onclick="toggleAccordion(this)">
                            <span><i class="fas fa-globe"></i> Page Preview</span>
                            <i class="fas fa-chevron-down toggle-icon"></i>
                        </div>
                        <div class="accordion-body-custom" style="display: block;">
                            <div class="page-preview" style="background: var(--bg-glass); border-radius: var(--radius-md); padding: 1.5rem; border: 1px solid var(--border-color);">
                                <!-- Favicon and Title -->
                                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                                    <div class="favicon-placeholder" style="width: 32px; height: 32px; background: var(--primary); border-radius: 6px; display: flex; align-items: center; justify-content: center;">
                                        <i class="fas fa-globe" style="color: white; font-size: 0.9rem;"></i>
                                    </div>
                                    <div style="flex: 1; min-width: 0;">
                                        <h4 style="margin: 0; font-size: 1.1rem; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                            ${pageMetadata.title || 'No title found'}
                                        </h4>
                                        <a href="${response.response?.final_url || '#'}" target="_blank" rel="noopener noreferrer" 
                                           style="font-size: 0.85rem; color: var(--primary); text-decoration: none; display: flex; align-items: center; gap: 0.25rem;">
                                            ${response.response?.final_url || response.target_domain || 'Unknown URL'}
                                            <i class="fas fa-external-link-alt" style="font-size: 0.7rem;"></i>
                                        </a>
                                    </div>
                                </div>

                                <!-- Description -->
                                <div class="page-description" style="margin-bottom: 1rem;">
                                    <p style="margin: 0; color: var(--text-secondary); font-size: 0.95rem; line-height: 1.6;">
                                        ${pageMetadata.description || '<em style="opacity: 0.6;">No description available</em>'}
                                    </p>
                                </div>

                                <!-- Meta Tags Grid -->
                                <div class="meta-tags-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
                                    <div class="meta-tag-item" style="background: var(--bg-secondary); padding: 0.75rem; border-radius: var(--radius-sm);">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Status</div>
                                        <div style="font-weight: 600; color: ${response.response?.status_code === 200 ? 'var(--success)' : 'var(--danger)'};">
                                            <i class="fas fa-${response.response?.status_code === 200 ? 'check-circle' : 'times-circle'}"></i>
                                            ${response.response?.status_code || 'N/A'}
                                        </div>
                                    </div>
                                    <div class="meta-tag-item" style="background: var(--bg-secondary); padding: 0.75rem; border-radius: var(--radius-sm);">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Size</div>
                                        <div style="font-weight: 600;">
                                            <i class="fas fa-file-code" style="color: var(--info);"></i>
                                            ${response.response?.content_length ? this.formatBytes(response.response.content_length) : 'N/A'}
                                        </div>
                                    </div>
                                    <div class="meta-tag-item" style="background: var(--bg-secondary); padding: 0.75rem; border-radius: var(--radius-sm);">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Language</div>
                                        <div style="font-weight: 600;">
                                            <i class="fas fa-language" style="color: var(--warning);"></i>
                                            ${pageMetadata.language || 'N/A'}
                                        </div>
                                    </div>
                                    <div class="meta-tag-item" style="background: var(--bg-secondary); padding: 0.75rem; border-radius: var(--radius-sm);">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Charset</div>
                                        <div style="font-weight: 600;">
                                            <i class="fas fa-code" style="color: var(--primary);"></i>
                                            ${pageMetadata.charset || 'N/A'}
                                        </div>
                                    </div>
                                </div>

                                <!-- Keywords (if available) -->
                                ${pageMetadata.keywords ? `
                                    <div class="keywords-section" style="margin-bottom: 1rem;">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem;">Keywords</div>
                                        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                            ${pageMetadata.keywords.split(',').slice(0, 8).map(kw => 
                                                `<span style="background: var(--primary-alpha); color: var(--primary); padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem;">${kw.trim()}</span>`
                                            ).join('')}
                                            ${pageMetadata.keywords.split(',').length > 8 ? `<span style="color: var(--text-muted); font-size: 0.8rem;">+${pageMetadata.keywords.split(',').length - 8} more</span>` : ''}
                                        </div>
                                    </div>
                                ` : ''}

                                <!-- Open Graph / Social Preview (if available) -->
                                ${pageMetadata.ogImage ? `
                                    <div class="og-preview" style="margin-bottom: 1rem;">
                                        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem;">Social Preview</div>
                                        <div style="background: var(--bg-secondary); border-radius: var(--radius-sm); overflow: hidden; border: 1px solid var(--border-color);">
                                            <img src="${pageMetadata.ogImage}" alt="OG Image" style="width: 100%; max-height: 200px; object-fit: cover;" onerror="this.parentElement.style.display='none'">
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    <!-- View Source Section -->
                    <div class="accordion-item-custom">
                        <div class="accordion-header-custom" onclick="toggleAccordion(this)">
                            <span><i class="fas fa-code"></i> View Page Source</span>
                            <i class="fas fa-chevron-down toggle-icon"></i>
                        </div>
                        <div class="accordion-body-custom">
                            <div class="source-controls" style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
                                <button class="btn-custom btn-sm btn-secondary" onclick="AnonymityRequest.copySource()">
                                    <i class="fas fa-copy"></i> Copy Source
                                </button>
                                <button class="btn-custom btn-sm btn-secondary" onclick="AnonymityRequest.downloadSource()">
                                    <i class="fas fa-download"></i> Download HTML
                                </button>
                                <button class="btn-custom btn-sm btn-secondary" onclick="AnonymityRequest.toggleWordWrap(this)">
                                    <i class="fas fa-text-width"></i> Word Wrap
                                </button>
                            </div>
                            <div class="source-info" style="display: flex; gap: 1rem; margin-bottom: 0.75rem; font-size: 0.85rem; color: var(--text-muted);">
                                <span><i class="fas fa-file-alt"></i> ${response.response?.content_length?.toLocaleString() || 0} characters</span>
                                <span><i class="fas fa-code"></i> ${this.countHtmlElements(response.response?.content)} elements</span>
                            </div>
                            <div class="code-block source-code-block" style="max-height: 400px; overflow: auto;">
                                <pre id="source-code" style="white-space: pre; margin: 0;">${this.escapeHtml(response.response?.content || 'No content available')}</pre>
                            </div>
                        </div>
                    </div>

                    <!-- Policy Metadata Section -->
                    <div class="accordion-item-custom">
                        <div class="accordion-header-custom" onclick="toggleAccordion(this)">
                            <span><i class="fas fa-shield-alt"></i> Policy Metadata</span>
                            <i class="fas fa-chevron-down toggle-icon"></i>
                        </div>
                        <div class="accordion-body-custom">
                            <div class="policy-info" style="display: grid; gap: 0.75rem;">
                                <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                                    <span style="color: var(--text-muted);">Risk Level</span>
                                    <span class="badge-custom badge-${this.getRiskBadgeClass(response.policy_metadata?.risk_level)}">${response.policy_metadata?.risk_level || 'N/A'}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                                    <span style="color: var(--text-muted);">Risk Score</span>
                                    <span style="font-weight: 600;">${response.policy_metadata?.risk_score?.toFixed(2) || 'N/A'}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                                    <span style="color: var(--text-muted);">Suggested Backend</span>
                                    <span class="badge-custom badge-info">${response.policy_metadata?.suggested_backend || 'N/A'}</span>
                                </div>
                                <div style="padding: 0.5rem 0;">
                                    <span style="color: var(--text-muted);">Reason</span>
                                    <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">${response.policy_metadata?.reason || 'N/A'}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Performance Metrics Section -->
                    <div class="accordion-item-custom">
                        <div class="accordion-header-custom" onclick="toggleAccordion(this)">
                            <span><i class="fas fa-tachometer-alt"></i> Performance Metrics</span>
                            <i class="fas fa-chevron-down toggle-icon"></i>
                        </div>
                        <div class="accordion-body-custom">
                            <div class="performance-metrics" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                                <div class="metric-card" style="text-align: center; padding: 1rem; background: var(--bg-glass); border-radius: var(--radius-sm);">
                                    <div style="font-size: 1.5rem; font-weight: 700; color: var(--primary);">${response.performance?.total_time?.toFixed(2) || 'N/A'}s</div>
                                    <div style="font-size: 0.85rem; color: var(--text-muted);">Total Time</div>
                                </div>
                                <div class="metric-card" style="text-align: center; padding: 1rem; background: var(--bg-glass); border-radius: var(--radius-sm);">
                                    <div style="font-size: 1.5rem; font-weight: 700, color: var(--success);">${response.performance?.execution_time?.toFixed(2) || 'N/A'}s</div>
                                    <div style="font-size: 0.85rem; color: var(--text-muted);">Execution Time</div>
                                </div>
                                <div class="metric-card" style="text-align: center; padding: 1rem; background: var(--bg-glass); border-radius: var(--radius-sm);">
                                    <div style="font-size: 1.5rem; font-weight: 700; color: var(--warning);">${response.performance?.policy_evaluation_time?.toFixed(4) || 'N/A'}s</div>
                                    <div style="font-size: 0.85rem; color: var(--text-muted);">Policy Eval</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Store response for copy/download functions
            this.lastResponse = response;

        } else {
            resultsDiv.innerHTML = `
                <div class="alert-custom alert-danger-custom">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>Request Failed</strong>
                        <p class="mb-0 mt-1">${response.error || response.message || 'Unknown error'}</p>
                        ${response.reason ? `<p class="mb-0" style="font-size: 0.9rem; opacity: 0.8;">${response.reason}</p>` : ''}
                    </div>
                </div>
            `;
        }

        resultsCard.style.display = 'block';
        resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },

    // Extract metadata from HTML content
    extractPageMetadata(html) {
        if (!html) return {};

        const metadata = {};

        // Extract title
        const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
        metadata.title = titleMatch ? this.decodeHtmlEntities(titleMatch[1].trim()) : null;

        // Extract meta description
        const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i) ||
                          html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["'][^>]*>/i);
        metadata.description = descMatch ? this.decodeHtmlEntities(descMatch[1].trim()) : null;

        // Extract meta keywords
        const keywordsMatch = html.match(/<meta[^>]*name=["']keywords["'][^>]*content=["']([^"']*)["'][^>]*>/i) ||
                              html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']keywords["'][^>]*>/i);
        metadata.keywords = keywordsMatch ? keywordsMatch[1].trim() : null;

        // Extract charset
        const charsetMatch = html.match(/<meta[^>]*charset=["']?([^"'\s>]+)["']?[^>]*>/i) ||
                             html.match(/<meta[^>]*content=["'][^"']*charset=([^"'\s;]+)[^"']*["'][^>]*>/i);
        metadata.charset = charsetMatch ? charsetMatch[1].toUpperCase() : null;

        // Extract language
        const langMatch = html.match(/<html[^>]*lang=["']([^"']*)["'][^>]*>/i);
        metadata.language = langMatch ? langMatch[1].toUpperCase() : null;

        // Extract Open Graph image
        const ogImageMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["'][^>]*>/i) ||
                             html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*property=["']og:image["'][^>]*>/i);
        metadata.ogImage = ogImageMatch ? ogImageMatch[1] : null;

        // Extract Open Graph title (fallback for title)
        if (!metadata.title) {
            const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["'][^>]*>/i);
            metadata.title = ogTitleMatch ? this.decodeHtmlEntities(ogTitleMatch[1].trim()) : null;
        }

        // Extract Open Graph description (fallback for description)
        if (!metadata.description) {
            const ogDescMatch = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["'][^>]*>/i);
            metadata.description = ogDescMatch ? this.decodeHtmlEntities(ogDescMatch[1].trim()) : null;
        }

        return metadata;
    },

    // Decode HTML entities
    decodeHtmlEntities(text) {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = text;
        return textarea.value;
    },

    // Format bytes to human readable
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Count HTML elements
    countHtmlElements(html) {
        if (!html) return 0;
        const matches = html.match(/<[a-z][^>]*>/gi);
        return matches ? matches.length : 0;
    },

    // Escape HTML for display
    escapeHtml(html) {
        if (!html) return '';
        const div = document.createElement('div');
        div.textContent = html;
        return div.innerHTML;
    },

    // Copy source to clipboard
    copySource() {
        if (this.lastResponse?.response?.content) {
            navigator.clipboard.writeText(this.lastResponse.response.content)
                .then(() => Toast.success('Source code copied to clipboard!'))
                .catch(() => Toast.error('Failed to copy source code'));
        }
    },

    // Download source as HTML file
    downloadSource() {
        if (this.lastResponse?.response?.content) {
            const blob = new Blob([this.lastResponse.response.content], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${this.lastResponse.target_domain || 'page'}_source.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            Toast.success('HTML file downloaded!');
        }
    },

    // Toggle word wrap in source view
    toggleWordWrap(btn) {
        const sourceCode = document.getElementById('source-code');
        if (sourceCode) {
            const isWrapped = sourceCode.style.whiteSpace === 'pre-wrap';
            sourceCode.style.whiteSpace = isWrapped ? 'pre' : 'pre-wrap';
            btn.classList.toggle('active', !isWrapped);
            Toast.info(isWrapped ? 'Word wrap disabled' : 'Word wrap enabled');
        }
    },

    // Store last response for copy/download
    lastResponse: null,

    formatResponseContent(response) {
        if (!response) return 'No response data';
        
        const displayResponse = { ...response };
        if (displayResponse.content && displayResponse.content.length > 500) {
            displayResponse.content = displayResponse.content.substring(0, 500) + '... [truncated]';
        }
        return JSON.stringify(displayResponse, null, 2);
    },

    getRiskBadgeClass(riskLevel) {
        const classes = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'danger'
        };
        return classes[riskLevel] || 'info';
    }

};

// ============================================
// Backend Testing
// ============================================

const BackendTester = {
    async test(backendType) {
        const button = document.querySelector(`[data-backend="${backendType}"]`);
        const resultsDiv = document.getElementById('test-results');
        
        if (!button || !resultsDiv) return;

        const originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner" style="width: 16px; height: 16px;"></span> Testing...';
        button.disabled = true;

        try {
            const result = await API.post('/test-connection', { backend: backendType });
            
            resultsDiv.innerHTML = `
                <div class="alert-custom ${result.working ? 'alert-success-custom' : 'alert-danger-custom'}">
                    <i class="fas ${result.working ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                    <div>
                        <strong>${backendType.toUpperCase()}</strong>
                        <span>${result.working ? 'Working' : 'Failed'}</span>
                        ${result.working ? `<span class="badge-custom badge-info ms-2">${result.response_time?.toFixed(2)}s</span>` : ''}
                    </div>
                </div>
            `;

            if (result.working) {
                Toast.success(`${backendType.toUpperCase()} backend is working!`);
            } else {
                Toast.warning(`${backendType.toUpperCase()} backend test failed`);
            }
        } catch (error) {
            resultsDiv.innerHTML = `
                <div class="alert-custom alert-danger-custom">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>Test failed: ${error.message}</span>
                </div>
            `;
            Toast.error('Backend test failed');
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
        }
    },

    init() {
        document.querySelectorAll('.test-backend').forEach(btn => {
            btn.addEventListener('click', () => {
                const backend = btn.getAttribute('data-backend');
                this.test(backend);
            });
        });
    }
};

// ============================================
// Policy Tester
// ============================================

const PolicyTester = {
    init() {
        const form = document.getElementById('policy-test-form');
        if (form) {
            form.addEventListener('submit', (e) => this.handleSubmit(e));
        }
    },

    async handleSubmit(e) {
        e.preventDefault();
        
        const testData = {
            target_url: document.getElementById('test-url').value,
            risk_level: document.getElementById('test-risk-level').value,
            time_of_day: parseInt(document.getElementById('test-time').value)
        };

        try {
            const response = await API.post('/policy/test', testData);
            this.displayResults(response);
        } catch (error) {
            Toast.error('Policy test failed: ' + error.message);
        }
    },

    displayResults(response) {
        const resultsDiv = document.getElementById('test-results');
        if (!resultsDiv) return;

        const result = response.test_result;
        const allowed = result.allowed;

        resultsDiv.innerHTML = `
            <div class="alert-custom ${allowed ? 'alert-success-custom' : 'alert-danger-custom'} mb-3">
                <i class="fas ${allowed ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                <div>
                    <strong>Policy Decision: ${allowed ? 'ALLOWED' : 'DENIED'}</strong>
                    <div class="mt-1" style="font-size: 0.9rem;">
                        <div><strong>Reason:</strong> ${result.reason}</div>
                        <div><strong>Risk Score:</strong> ${result.risk_score?.toFixed(2) || 'N/A'}</div>
                        <div><strong>Suggested Backend:</strong> <span class="badge-custom badge-info">${result.suggested_backend || 'N/A'}</span></div>
                    </div>
                </div>
            </div>

            <div class="glass-card">
                <div class="card-header-custom">
                    <h5><i class="fas fa-code"></i> Test Input</h5>
                </div>
                <div class="card-body-custom">
                    <div class="code-block">
                        <pre>${JSON.stringify(response.sample_input, null, 2)}</pre>
                    </div>
                </div>
            </div>
        `;
    }
};

// Handle anonymity request
async function handleAnonymityRequest(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    
    // Show loading state
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
    submitBtn.disabled = true;
    
    const formData = new FormData(form);
    const data = {
        url: formData.get('url'),
        user_id: formData.get('user_id'),
        purpose: formData.get('purpose')
    };
    
    try {
        const response = await apiClient.post('/api/anonymity/request', data);
        
        console.log('API Response:', response); // Log the response

        if (response.success || response.status === 'success') {
            // Handle different possible property names for time
            const responseTime = response.response_time || response.time || response.elapsed_time || 'N/A';
            const timeDisplay = typeof responseTime === 'number' ? responseTime.toFixed(2) + 's' : responseTime;
            
            showToast('Request completed successfully!', 'success');
            
            // Update results section if it exists
            const resultsSection = document.getElementById('request-results');
            if (resultsSection) {
                resultsSection.innerHTML = `
                    <div class="result-success">
                        <i class="fas fa-check-circle"></i>
                        <h4>Request Successful!</h4>
                        <div class="result-details">
                            <span class="result-tag">Backend: ${response.backend || response.method || 'tor'}</span>
                            <span class="result-tag">Time: ${timeDisplay}</span>
                            <span class="result-tag">${response.fingerprint_protected ? 'FP Protected' : 'Standard'}</span>
                        </div>
                        ${response.ip_address ? `<p class="result-ip">Exit IP: ${response.ip_address}</p>` : ''}
                        ${response.status_code ? `<p>Status Code: ${response.status_code}</p>` : ''}
                    </div>
                `;
                resultsSection.style.display = 'block';
            }
        } else {
            throw new Error(response.error || response.message || 'Request failed');
        }
    } catch (error) {
        showToast(error.message || 'Failed to send request', 'error');
        
        const resultsSection = document.getElementById('request-results');
        if (resultsSection) {
            resultsSection.innerHTML = `
                <div class="result-error">
                    <i class="fas fa-times-circle"></i>
                    <h4>Request Failed</h4>
                    <p>${error.message}</p>
                </div>
            `;
            resultsSection.style.display = 'block';
        }
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

// ============================================
// Monitoring Page Manager
// ============================================

const MonitoringStats = {
    updateInterval: null,

    async init() {
        await this.loadStats();
        this.startAutoRefresh(10000);
    },

    async loadStats() {
        try {
            const [systemStatus, userStats] = await Promise.all([
                API.get('/system-status'),
                API.get('/user-stats')
            ]);

            console.log('System Status Response:', systemStatus);
            console.log('User Stats Response:', userStats);

            this.updateSystemStatus(systemStatus);
            this.updateBackendStats(userStats);
            this.updatePerformanceMetrics(userStats);
            this.updateActivityLog(userStats.recent_requests || []);
            this.updateLastRefreshTime();

        } catch (error) {
            console.error('Failed to load monitoring stats:', error);
            Toast.error('Failed to load monitoring data');
        }
    },

    updateSystemStatus(data) {
        console.log('Parsing system status:', data);
        
        // Policy Engine - check active, healthy, or status
        const policyEngineOnline = (data.policy_engine?.active === true) ||
                                   (data.policy_engine?.healthy === true) || 
                                   (data.policy_engine?.status === 'active') ||
                                   (data.policy_engine?.opa_available === true);

        // Tor Network - check tor_connectivity first, then proxy_manager.backends.tor.working
        const torOnline = (data.tor_connectivity?.connected === true) ||
                         (data.tor_connectivity?.is_tor === true) ||
                         (data.proxy_manager?.backends?.tor?.working === true);

        // Proxy Manager - it's online if we have the proxy_manager object with active status
        const proxyOnline = (data.proxy_manager?.active === true);

        // Fingerprint Protection - defaults to enabled (true)
        const fingerprintOnline = data.fingerprint_manager?.protection_enabled !== false;

        console.log('Status Results:', {
            policyEngine: policyEngineOnline,
            tor: torOnline,
            proxy: proxyOnline,
            fingerprint: fingerprintOnline
        });

        this.updateStatusIndicator('policy-engine-status', policyEngineOnline);
        this.updateStatusIndicator('tor-status', torOnline);
        this.updateStatusIndicator('proxy-status', proxyOnline);
        this.updateStatusIndicator('fingerprint-status', fingerprintOnline);
    },

    updateStatusIndicator(elementId, isOnline) {
        const element = document.getElementById(elementId);
        if (!element) {
            console.warn(`Element not found: ${elementId}`);
            return;
        }

        const statusDot = element.querySelector('.status-dot');
        const statusText = element.querySelector('.status-text');
        
        if (statusDot) {
            statusDot.className = `status-dot ${isOnline ? 'online' : 'offline'}`;
        }
        if (statusText) {
            statusText.textContent = isOnline ? 'Online' : 'Offline';
            statusText.style.color = isOnline ? 'var(--success)' : 'var(--danger)';
        }
    },

    updateBackendStats(userStats) {
        const backendUsage = userStats.backend_usage || {};
        
        console.log('Backend Usage:', backendUsage);

        this.animateCounter('tor-count', backendUsage.tor || 0);
        this.animateCounter('direct-count', backendUsage.direct || 0);
        this.animateCounter('proxy-count', backendUsage.proxy_chain || backendUsage.proxy || 0);
        this.animateCounter('vpn-count', backendUsage.vpn || 0);

        this.animateCounter('total-requests', userStats.total_requests || 0);
        this.animateCounter('successful-requests', userStats.successful_requests || 0);
        this.animateCounter('failed-requests', userStats.failed_requests || 0);
    },

    updatePerformanceMetrics(userStats) {
        const avgTime = userStats.average_response_time;
        const avgTimeElement = document.getElementById('avg-response-time');
        if (avgTimeElement) {
            avgTimeElement.textContent = `${(avgTime || 0).toFixed(2)}s`;
        }

        const successRate = userStats.success_rate;
        const successRateElement = document.getElementById('success-rate');
        if (successRateElement) {
            successRateElement.textContent = `${(successRate || 0).toFixed(1)}%`;
        }

        const lastRequest = userStats.last_request;
        const lastRequestElement = document.getElementById('last-request-time');
        if (lastRequestElement && lastRequest) {
            lastRequestElement.textContent = this.formatRelativeTime(lastRequest);
        }
    },

    updateActivityLog(activities) {
        const activityContainer = document.getElementById('activity-log');
        if (!activityContainer) return;

        console.log('Activity Log:', activities);

        // Render empty state if no activities
        if (!activities || activities.length === 0) {
            activityContainer.innerHTML = `
                <div class="activity-empty">
                    <i class="fas fa-inbox"></i>
                    <p>No recent activity. Make some requests from the Dashboard!</p>
                </div>
            `;
            return;
        }

        // Render activity items
        activityContainer.innerHTML = activities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon ${activity.success ? 'success' : 'error'}">
                    <i class="fas fa-${activity.success ? 'check' : 'times'}"></i>
                </div>
                <div class="activity-info">
                    <div class="activity-title" title="${this.escapeHtml(activity.url)}">
                        ${this.escapeHtml(activity.target_domain || activity.url || 'Unknown')}
                    </div>
                    <div class="activity-meta">
                        <span class="badge-custom badge-${this.getBackendBadgeClass(activity.backend_used)}" style="font-size: 0.7rem; padding: 0.15rem 0.5rem;">
                            ${this.formatBackendName(activity.backend_used)}
                        </span>
                        ${activity.status_code ? `
                            <span class="badge-custom badge-${activity.status_code === 200 ? 'success' : 'warning'}" style="font-size: 0.7rem; padding: 0.15rem 0.5rem; margin-left: 0.25rem;">
                                ${activity.status_code}
                            </span>
                        ` : ''}
                        ${activity.response_time ? `
                            <span style="margin-left: 0.5rem; color: var(--text-muted); font-size: 0.8rem;">
                                <i class="fas fa-clock"></i> ${activity.response_time.toFixed(2)}s
                            </span>
                        ` : ''}
                        ${activity.fingerprint_protection ? `
                            <span style="margin-left: 0.5rem; color: var(--warning); font-size: 0.8rem;" title="Fingerprint Protected">
                                <i class="fas fa-shield-alt"></i>
                            </span>
                        ` : ''}
                        ${activity.risk_level && activity.risk_level !== 'unknown' ? `
                            <span class="badge-custom badge-${this.getRiskBadgeClass(activity.risk_level)}" style="font-size: 0.7rem; padding: 0.15rem 0.5rem; margin-left: 0.25rem;">
                                ${activity.risk_level}
                            </span>
                        ` : ''}
                    </div>
                    ${activity.error ? `
                        <div class="activity-error" style="color: var(--danger); font-size: 0.8rem; margin-top: 0.25rem;">
                            <i class="fas fa-exclamation-circle"></i> ${this.escapeHtml(activity.error)}
                        </div>
                    ` : ''}
                </div>
                <div class="activity-time">
                    ${activity.timestamp ? this.formatRelativeTime(activity.timestamp) : 'Just now'}
                </div>
            </div>
        `).join('');
    },

    formatBackendName(backend) {
        const names = {
            'tor': 'Tor',
            'direct': 'Direct',
            'proxy': 'Proxy',
            'proxy_chain': 'Proxy Chain',
            'vpn': 'VPN',
            'unknown': 'Unknown'
        };
        return names[backend?.toLowerCase()] || backend || 'Unknown';
    },

    getBackendBadgeClass(backend) {
        const classes = {
            'tor': 'info',
            'direct': 'success',
            'proxy': 'warning',
            'proxy_chain': 'warning',
            'vpn': 'primary',
            'unknown': 'secondary'
        };
        return classes[backend?.toLowerCase()] || 'secondary';
    },

    getRiskBadgeClass(riskLevel) {
        const classes = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'danger'
        };
        return classes[riskLevel?.toLowerCase()] || 'secondary';
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    animateCounter(elementId, targetValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        
        if (currentValue === targetValue) return;

        const duration = 500;
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(currentValue + (targetValue - currentValue) * easeOut);
            
            element.textContent = value;

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    },

    formatRelativeTime(dateString) {
        if (!dateString) return 'Never';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffSecs = Math.floor(diffMs / 1000);
        const diffMins = Math.floor(diffSecs / 60);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffSecs < 5) return 'Just now';
        if (diffSecs < 60) return `${diffSecs}s ago`;
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        return date.toLocaleDateString();
    },

    updateLastRefreshTime() {
        const element = document.getElementById('last-refresh');
        if (element) {
            element.textContent = new Date().toLocaleTimeString();
        }
    },

    startAutoRefresh(interval = 10000) {
        this.stopAutoRefresh();
        this.updateInterval = setInterval(() => this.loadStats(), interval);
    },

    stopAutoRefresh() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    },

    async clearHistory() {
        if (!confirm('Are you sure you want to clear your request history?')) {
            return;
        }

        try {
            const response = await API.post('/clear-history', {});
            
            if (response.success) {
                Toast.success('History cleared successfully');
                await this.loadStats(); // Refresh the display
            } else {
                Toast.error(response.error || 'Failed to clear history');
            }
        } catch (error) {
            console.error('Failed to clear history:', error);
            Toast.error('Failed to clear history');
        }
    }
};

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    ThemeManager.init();
    
    // Initialize toast container
    Toast.init();
    
    // Initialize components based on current page
    const path = window.location.pathname;
    
    if (path === '/' || path.includes('dashboard')) {
        SystemStatus.load();
        SystemStatus.startAutoRefresh();
        UserStats.load();
        AnonymityRequest.init();
        BackendTester.init();
    }
    
    if (path.includes('monitoring')) {
        MonitoringStats.init();
    }
    
    if (path.includes('policy')) {
        PolicyTester.init();
    }
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    SystemStatus.stopAutoRefresh();
    if (typeof MonitoringStats !== 'undefined') {
        MonitoringStats.stopAutoRefresh();
    }
});
