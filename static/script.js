document.addEventListener("DOMContentLoaded", function () {
    const dosCtx = document.getElementById("dosChart").getContext("2d");
    const portCtx = document.getElementById("portScanChart").getContext("2d");

    const dosChart = new Chart(dosCtx, {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                label: "DoS Attack Count",
                data: [],
                backgroundColor: "red",
            }]
        }
    });

    const portScanChart = new Chart(portCtx, {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                label: "Port Scan Count",
                data: [],
                backgroundColor: "orange",
            }]
        }
    });

    function combineCounts(signature, anomaly) {
        const combined = {};

        signature.forEach(entry => {
            combined[entry.ip] = (combined[entry.ip] || 0) + entry.count;
        });

        anomaly.forEach(entry => {
            combined[entry.ip] = (combined[entry.ip] || 0) + entry.count;
        });

        return Object.entries(combined).map(([ip, count]) => ({ ip, count }));
    }

    function updateCharts() {
        fetch("/data")
            .then(response => response.json())
            .then(data => {
                const dosCombined = combineCounts(data.dos_signature, data.dos_anomaly);
                const portCombined = combineCounts(data.port_signature, data.port_anomaly);

                // Update DoS chart
                dosChart.data.labels = dosCombined.map(entry => entry.ip);
                dosChart.data.datasets[0].data = dosCombined.map(entry => entry.count);
                dosChart.update();

                // Update Port Scan chart
                portScanChart.data.labels = portCombined.map(entry => entry.ip);
                portScanChart.data.datasets[0].data = portCombined.map(entry => entry.count);
                portScanChart.update();
            })
            .catch(error => console.error("Error fetching data:", error));
    }

    setInterval(updateCharts, 5000);
});