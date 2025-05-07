/**
 * Data Persistence Module
 * 
 * This module provides functions to store and retrieve data from localStorage
 * to maintain state between page navigations in the dashboard.
 */

// Namespace for our persistence functions
const DataPersistence = {
    // Store data in localStorage with a specific key
    saveData: function(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            console.log(`Data saved with key: ${key}`);
            return true;
        } catch (error) {
            console.error(`Error saving data with key ${key}:`, error);
            return false;
        }
    },

    // Retrieve data from localStorage by key
    loadData: function(key) {
        try {
            const data = localStorage.getItem(key);
            if (data) {
                return JSON.parse(data);
            }
            return null;
        } catch (error) {
            console.error(`Error loading data with key ${key}:`, error);
            return null;
        }
    },

    // Clear data for a specific key
    clearData: function(key) {
        try {
            localStorage.removeItem(key);
            console.log(`Data cleared for key: ${key}`);
            return true;
        } catch (error) {
            console.error(`Error clearing data with key ${key}:`, error);
            return false;
        }
    },

    // Clear all data stored by this application
    clearAllData: function() {
        try {
            localStorage.clear();
            console.log('All data cleared');
            return true;
        } catch (error) {
            console.error('Error clearing all data:', error);
            return false;
        }
    }
};

// Memory Protection specific functions
const MemoryProtectionData = {
    // Key for memory protection data in localStorage
    STORAGE_KEY: 'memory_protection_data',

    // Save memory protection analysis data
    saveAnalysis: function(targetId, pid, data) {
        // Get existing data or initialize empty object
        const allData = DataPersistence.loadData(this.STORAGE_KEY) || {};
        
        // Create target entry if it doesn't exist
        if (!allData[targetId]) {
            allData[targetId] = {};
        }
        
        // Add or update data for this PID
        allData[targetId][pid] = {
            data: data,
            timestamp: new Date().toISOString()
        };
        
        // Save back to localStorage
        return DataPersistence.saveData(this.STORAGE_KEY, allData);
    },

    // Load memory protection analysis data for a specific target and PID
    loadAnalysis: function(targetId, pid) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId] && allData[targetId][pid]) {
            return allData[targetId][pid].data;
        }
        return null;
    },

    // Check if we have data for a specific target and PID
    hasAnalysisData: function(targetId, pid) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        return !!(allData && allData[targetId] && allData[targetId][pid]);
    },

    // Clear analysis data for a specific target and PID
    clearAnalysis: function(targetId, pid) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId] && allData[targetId][pid]) {
            delete allData[targetId][pid];
            return DataPersistence.saveData(this.STORAGE_KEY, allData);
        }
        return true;
    },

    // Clear all memory protection analysis data for a target
    clearTargetAnalyses: function(targetId) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId]) {
            delete allData[targetId];
            return DataPersistence.saveData(this.STORAGE_KEY, allData);
        }
        return true;
    },

    // Clear all memory protection analysis data
    clearAllAnalyses: function() {
        return DataPersistence.clearData(this.STORAGE_KEY);
    }
};

// Network Devices specific functions
const NetworkDevicesData = {
    // Key for network devices data in localStorage
    STORAGE_KEY: 'network_devices_data',

    // Save network devices data
    saveDevices: function(targetId, data) {
        // Get existing data or initialize empty object
        const allData = DataPersistence.loadData(this.STORAGE_KEY) || {};
        
        // Add or update data for this target
        allData[targetId] = {
            data: data,
            timestamp: new Date().toISOString()
        };
        
        // Save back to localStorage
        return DataPersistence.saveData(this.STORAGE_KEY, allData);
    },

    // Load network devices data for a specific target
    loadDevices: function(targetId) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId]) {
            return allData[targetId].data;
        }
        return null;
    },

    // Check if we have data for a specific target
    hasDevicesData: function(targetId) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        return !!(allData && allData[targetId]);
    },

    // Clear devices data for a specific target
    clearDevices: function(targetId) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId]) {
            delete allData[targetId];
            return DataPersistence.saveData(this.STORAGE_KEY, allData);
        }
        return true;
    },

    // Clear all network devices data
    clearAllDevices: function() {
        return DataPersistence.clearData(this.STORAGE_KEY);
    }
};

// OS Info specific functions
const OsInfoData = {
    // Key for OS info data in localStorage
    STORAGE_KEY: 'os_info_data',

    // Save OS info data
    saveInfo: function(targetId, section, data) {
        // Get existing data or initialize empty object
        const allData = DataPersistence.loadData(this.STORAGE_KEY) || {};
        
        // Create target entry if it doesn't exist
        if (!allData[targetId]) {
            allData[targetId] = {};
        }
        
        // Add or update data for this section
        allData[targetId][section] = {
            data: data,
            timestamp: new Date().toISOString()
        };
        
        // Save back to localStorage
        return DataPersistence.saveData(this.STORAGE_KEY, allData);
    },

    // Load OS info data for a specific target and section
    loadInfo: function(targetId, section) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId] && allData[targetId][section]) {
            return allData[targetId][section].data;
        }
        return null;
    },

    // Check if we have data for a specific target and section
    hasInfoData: function(targetId, section) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        return !!(allData && allData[targetId] && allData[targetId][section]);
    },

    // Clear info data for a specific target and section
    clearInfo: function(targetId, section) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId] && allData[targetId][section]) {
            delete allData[targetId][section];
            return DataPersistence.saveData(this.STORAGE_KEY, allData);
        }
        return true;
    },

    // Clear all OS info data for a target
    clearTargetInfo: function(targetId) {
        const allData = DataPersistence.loadData(this.STORAGE_KEY);
        if (allData && allData[targetId]) {
            delete allData[targetId];
            return DataPersistence.saveData(this.STORAGE_KEY, allData);
        }
        return true;
    },

    // Clear all OS info data
    clearAllInfo: function() {
        return DataPersistence.clearData(this.STORAGE_KEY);
    }
};
