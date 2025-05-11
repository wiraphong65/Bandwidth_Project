// State management
const state = {
  activeView: "queues",
  selectedItems: [], // เก็บ rule IDs ที่ถูกเลือก
  rules: [], // <--- เริ่มต้นเป็น array ว่าง จะถูก fetch มา
  searchQuery: "",
  currentBandwidth: {
    rx_bytes: 0, // <--- เริ่มต้นเป็น 0
    tx_bytes: 0  // <--- เริ่มต้นเป็น 0
  },
  activeInterface: "" // <--- จะถูกตั้งค่าตอน init
};

// DOM Elements (เหมือนเดิม)
const navItems = { /* ... */ };
const buttons = { /* ... */ };
const interfaceSelect = document.getElementById('interface');
const searchInput = document.getElementById('search-input');
const rulesTableBody = document.getElementById('rules-body');
const selectAllCheckbox = document.getElementById('select-all');
const downloadValue = document.getElementById('download-value');
const uploadValue = document.getElementById('upload-value');

// --- API Call Functions ---
async function fetchInterfacesAndSetActive() {
    try {
        const response = await fetch('/api/interfaces'); // Endpoint ที่สร้างใน Flask
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();

        interfaceSelect.innerHTML = ''; // Clear existing options
        if (data.interfaces && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                interfaceSelect.appendChild(option);
            });

            if (data.active_interface && data.interfaces.includes(data.active_interface)) {
                state.activeInterface = data.active_interface;
                interfaceSelect.value = data.active_interface;
            } else if (data.interfaces.length > 0) { // Fallback
                state.activeInterface = data.interfaces[0];
                interfaceSelect.value = data.interfaces[0];
                // Optionally inform backend about this default selection
                await setActiveInterfaceOnBackend(state.activeInterface);
            }
        } else {
            const option = document.createElement('option');
            option.value = "";
            option.textContent = "No interfaces found";
            interfaceSelect.appendChild(option);
            state.activeInterface = ""; // No active interface
        }
    } catch (error) {
        console.error("Error fetching interfaces:", error);
        interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        state.activeInterface = "";
    }
}

async function setActiveInterfaceOnBackend(interfaceName) {
    try {
        const response = await fetch('/api/set_active_interface', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' /*, CSRF Header */ },
            body: JSON.stringify({ interface_name: interfaceName })
        });
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || `Failed to set active interface: ${response.status}`);
        }
        const result = await response.json();
        console.log("Backend setActiveInterface response:", result.message);
        // The backend /api/set_active_interface might trigger reapply rules or expect client to.
        // For this flow, we'll have client re-fetch rules.
    } catch (error) {
        console.error("Error setting active interface on backend:", error);
        // alert("Could not set active interface on server."); // Notify user
    }
}

async function fetchRules(interfaceName) {
    if (!interfaceName) {
        state.rules = [];
        renderRules();
        return;
    }
    try {
        const response = await fetch(`/api/rules/${interfaceName}`);
        if (!response.ok) {
            state.rules = [];
            if(response.status === 404) console.warn(`No rules found or invalid interface for GET /api/rules: ${interfaceName}`);
            else throw new Error(`HTTP error! status: ${response.status}`);
        } else {
            state.rules = await response.json();
        }
    } catch (error) {
        console.error(`Error fetching rules for ${interfaceName}:`, error);
        state.rules = []; // Clear rules on error
        // alert(`Could not load rules for ${interfaceName}.`);
    }
    renderRules(); // Render even if empty or error (renderRules should handle empty state)
    state.selectedItems = []; // Clear selection
    selectAllCheckbox.checked = false;
    updateButtonStates();
}

async function fetchBandwidthStats(interfaceName) {
    if (!interfaceName) {
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        updateBandwidthDisplay();
        return;
    }
    try {
        const response = await fetch(`/api/bandwidth_usage/${interfaceName}`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        state.currentBandwidth = {
            rx_bytes: data.rx_bytes || 0,
            tx_bytes: data.tx_bytes || 0
        };
    } catch (error) {
        console.error("Error fetching bandwidth stats:", error);
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 }; // Reset on error
    }
    updateBandwidthDisplay();
}


// Event Handlers (ปรับปรุง)
function setActiveView(view) { /* ... เหมือนเดิม ... */ }

function handleAddRule() {
    alert('Add new rule: Implement a modal to get rule details, then call an API.');
    // ตัวอย่างการเรียก API (หลังจากได้ข้อมูลจาก Modal)
    // const newRuleData = {
    //   name: "User Desktop",
    //   target: "192.168.1.100",
    //   rate: "5 Mbps",
    //   maxLimit: "10 Mbps", // หรือ map ไป burst/cburst
    //   enabled: true,
    //   direction: "download" // และ fields อื่นๆ ที่ API ต้องการ
    // };
    // if (state.activeInterface) {
    //   fetch(`/api/rules/${state.activeInterface}`, {
    //     method: 'POST',
    //     headers: { 'Content-Type': 'application/json' /* CSRF */ },
    //     body: JSON.stringify(newRuleData)
    //   })
    //   .then(response => {
    //     if (!response.ok) return response.json().then(err => { throw new Error(err.error || 'API Error')});
    //     return response.json();
    //   })
    //   .then(data => {
    //     console.log('Rule added:', data.message);
    //     fetchRules(state.activeInterface); // Refresh
    //   })
    //   .catch(error => {
    //     console.error('Error adding rule:', error);
    //     alert(`Error: ${error.message}`);
    //   });
    // }
}

async function handleRemoveRules() {
    if (state.selectedItems.length === 0 || !state.activeInterface) return;
    if (!confirm(`Are you sure you want to remove ${state.selectedItems.length} selected rule(s)?`)) return;

    const promises = state.selectedItems.map(ruleId =>
        fetch(`/api/rules/${state.activeInterface}/${ruleId}`, {
            method: 'DELETE' /*, headers: { CSRF } */
        }).then(response => {
            if (!response.ok) {
                console.error(`Failed to delete rule ${ruleId}. Status: ${response.status}`);
                return response.json().then(err => { throw new Error(err.error || `Failed for rule ${ruleId}`) });
            }
            return response.json();
        })
    );

    try {
        await Promise.all(promises);
        console.log("Selected rules deletion process completed.");
    } catch (error) {
        console.error("One or more rules failed to delete:", error);
        alert("Some rules could not be deleted. Check console for details.");
    } finally {
        state.selectedItems = []; // Clear selection regardless of individual failures
        fetchRules(state.activeInterface); // Refresh the list from server
    }
}

async function handleEnableRules() { // This toggles selected rules' DB `is_enabled` flag
    if (state.selectedItems.length === 0 || !state.activeInterface) return;

    const promises = state.selectedItems.map(ruleId => {
        // We don't know the current state to "toggle" in the backend in one go
        // The backend API /toggle will flip the current DB is_enabled state
        return fetch(`/api/rules/${state.activeInterface}/${ruleId}/toggle`, {
            method: 'POST' /*, headers: { CSRF } */
        }).then(response => {
            if (!response.ok) {
                console.error(`Failed to toggle rule ${ruleId}. Status: ${response.status}`);
                return response.json().then(err => { throw new Error(err.error || `Failed for rule ${ruleId}`) });
            }
            return response.json(); // API should return the updated rule
        });
    });
    
    try {
        const results = await Promise.all(promises);
        console.log("Selected rules toggle process completed.", results);
        // Instead of locally modifying, we rely on fetchRules to get the authoritative state
    } catch (error) {
        console.error("One or more rules failed to toggle:", error);
        alert("Some rules could not be toggled. Check console for details.");
    } finally {
        fetchRules(state.activeInterface); // Refresh list to show actual backend state
    }
}


async function handleInterfaceChange(e) {
    const newInterface = e.target.value;
    if (newInterface === state.activeInterface && newInterface !== "") return;

    console.log(`Interface changed to: ${newInterface}`);
    if (!newInterface) { // "No interfaces found" or empty selected
        state.activeInterface = "";
        state.rules = [];
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        renderRules();
        updateBandwidthDisplay();
        return;
    }

    await setActiveInterfaceOnBackend(newInterface); // Inform backend
    state.activeInterface = newInterface; // Update local state *after* successful backend update (or assume success)
    
    // Fetch new data for the new interface
    await fetchRules(state.activeInterface);
    await fetchBandwidthStats(state.activeInterface); // Fetch stats for the new interface
}


function handleSearch(e) { /* ... เหมือนเดิม, กรองจาก state.rules ที่ fetch มา ... */ }
function handleSelectAll(e) { /* ... เหมือนเดิม ... */ }
function handleRuleSelect(e, ruleId) { /* ... เหมือนเดิม ... */ }

// Rendering (ปรับปรุง status indicator เล็กน้อย)
function renderRules() {
    rulesTableBody.innerHTML = ''; // Clear existing rows

    const filteredRules = state.rules.filter(rule =>
        (rule.name && rule.name.toLowerCase().includes(state.searchQuery)) ||
        (rule.target && rule.target.toLowerCase().includes(state.searchQuery))
    );

    if (filteredRules.length === 0) {
        const row = rulesTableBody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6; // Number of columns
        cell.textContent = state.searchQuery ? "No rules match your search." : "No rules defined for this interface.";
        cell.style.textAlign = "center";
        cell.style.padding = "1rem";
        cell.style.color = "#64748b";
    } else {
        filteredRules.forEach(rule => {
            const row = rulesTableBody.insertRow();
            row.dataset.ruleId = rule.id; // Store id on the row for easy access

            // Checkbox cell
            const checkboxCell = row.insertCell();
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'checkbox';
            checkbox.value = rule.id; // Use value for easier processing if needed
            checkbox.checked = state.selectedItems.includes(String(rule.id)); // Ensure comparison with string ID
            checkbox.addEventListener('change', (e) => handleRuleSelect(e, String(rule.id)));
            checkboxCell.appendChild(checkbox);
            checkboxCell.classList.add('checkbox-column');


            // Data cells
            row.insertCell().textContent = rule.name || 'N/A';
            row.insertCell().textContent = rule.target || 'N/A';
            row.insertCell().textContent = rule.rate || 'N/A';
            row.insertCell().textContent = rule.maxLimit || 'N/A';

            const statusCell = row.insertCell();
            const statusIndicator = document.createElement('span');
            // 'enabled' from API now reflects true operational status
            statusIndicator.className = `status-indicator ${rule.enabled ? 'status-enabled' : 'status-disabled'}`;
            statusCell.appendChild(statusIndicator);
            statusCell.classList.add('status-column');
        });
    }
    selectAllCheckbox.checked = filteredRules.length > 0 && state.selectedItems.length === filteredRules.length;
    updateButtonStates();
}


function updateButtonStates() { /* ... เหมือนเดิม ... */ }
function updateBandwidthDisplay() { /* ... เหมือนเดิม ... */ }
function formatBytes(bytes, decimals = 2) { /* ... เหมือนเดิม ... */ }

// ลบ simulateBandwidthUpdates() ออก

// Initialize
async function init() {
    setupEventListeners();
    await fetchInterfacesAndSetActive(); // ดึง Interfaces, ตั้ง Active, แล้ว fetch data เริ่มต้น
    // fetchRules และ fetchBandwidthStats จะถูกเรียกภายใน fetchInterfacesAndSetActive หรือหลังจาก activeInterface ถูกตั้ง

    // ตั้ง Interval สำหรับ Bandwidth Stats (หลังจาก activeInterface ถูกตั้งค่าแล้ว)
    if (state.activeInterface) { // ตรวจสอบอีกครั้งว่ามี active interface
        setInterval(() => fetchBandwidthStats(state.activeInterface), 5000); // Poll every 5 seconds
    } else {
        console.log("No active interface to start polling bandwidth stats.");
    }
    renderRules(); // Render rules (อาจจะยังว่างถ้า fetch ไม่เสร็จ)
    updateButtonStates();
    updateBandwidthDisplay(); // แสดงค่า bandwidth เริ่มต้น (น่าจะเป็น 0)
}

// Start the application when DOM is loaded
document.addEventListener('DOMContentLoaded', init);