<template>
    <div @click.self="handleClickOutside">
        <div class="period-options" ref="periodOptionsRef">
            <button
                type="button" class="btn btn-light dropdown-toggle btn-period-toggle" data-bs-toggle="dropdown"
                aria-expanded="false"
            >
                {{ getDisplayPeriodText() }}&nbsp;
            </button>
            <ul class="dropdown-menu dropdown-menu-end">
                <li v-for="(item, key) in chartPeriodOptions" :key="key">
                    <button
                        type="button" 
                        class="dropdown-item" 
                        :class="{ active: chartPeriodHrs == key }"
                        @click="handlePeriodSelect(key)"
                    >
                        <template v-if="key === 'custom'">
                            <font-awesome-icon icon="calendar" class="me-2" />
                            {{ item }}
                        </template>
                        <template v-else>
                            {{ item }}
                        </template>
                    </button>
                </li>
            </ul>
            <div v-if="chartPeriodHrs === 'custom' && showDatePicker" class="custom-date-range" ref="datePickerRef">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="mb-0">
                        <font-awesome-icon icon="calendar-alt" class="me-2" />
                        {{ $t("Date Range") || "Date Range" }}
                    </h6>
                    <button 
                        type="button" 
                        class="btn-close" 
                        @click="showDatePicker = false"
                        aria-label="Close"
                    ></button>
                </div>
                <Datepicker 
                    v-model="dateRange" 
                    range 
                    :enableTimePicker="false"
                    :maxDate="new Date()"
                    @update:modelValue="applyCustomDateRange"
                />
            </div>
        </div>
        <div class="chart-wrapper" :class="{ loading: loading }">
            <Line :data="chartData" :options="chartOptions" />
        </div>
    </div>
</template>

<script lang="js">
import { BarController, BarElement, Chart, Filler, LinearScale, LineController, LineElement, PointElement, TimeScale, Tooltip } from "chart.js";
import "chartjs-adapter-dayjs-4";
import { Line } from "vue-chartjs";
import { UP, DOWN, PENDING, MAINTENANCE } from "../util.ts";
import Datepicker from '@vuepic/vue-datepicker';
import '@vuepic/vue-datepicker/dist/main.css';
import dayjs from "dayjs";

Chart.register(LineController, BarController, LineElement, PointElement, TimeScale, BarElement, LinearScale, Tooltip, Filler);

export default {
    components: { Line, Datepicker },
    props: {
        /** ID of monitor */
        monitorId: {
            type: Number,
            required: true,
        },
    },
    data() {
        return {

            loading: false,

            // Time period for the chart to display, in hours
            // Initial value is 0 as a workaround for triggering a data fetch on created()
            chartPeriodHrs: "0",

            chartPeriodOptions: {
                0: this.$t("recent"),
                3: "3h",
                6: "6h",
                24: "24h",
                168: "1w",
                custom: this.$t("Custom") || "Custom",
            },

            dateRange: [dayjs().subtract(7, 'day').toDate(), dayjs().toDate()],
            customPeriodHours: null,
            showDatePicker: false,

            chartRawData: null,
            chartDataFetchInterval: null,
        };
    },
    computed: {
        chartOptions() {
            return {
                responsive: true,
                maintainAspectRatio: false,
                onResize: (chart) => {
                    chart.canvas.parentNode.style.position = "relative";
                    if (screen.width < 576) {
                        chart.canvas.parentNode.style.height = "275px";
                    } else if (screen.width < 768) {
                        chart.canvas.parentNode.style.height = "320px";
                    } else if (screen.width < 992) {
                        chart.canvas.parentNode.style.height = "300px";
                    } else {
                        chart.canvas.parentNode.style.height = "250px";
                    }
                },
                layout: {
                    padding: {
                        left: 10,
                        right: 30,
                        top: 30,
                        bottom: 10,
                    },
                },

                elements: {
                    point: {
                        // Hide points on chart unless mouse-over
                        radius: 0,
                        hitRadius: 100,
                    },
                },
                scales: {
                    x: {
                        type: "time",
                        time: {
                            minUnit: "minute",
                            round: "second",
                            tooltipFormat: "YYYY-MM-DD HH:mm:ss",
                            displayFormats: {
                                minute: "HH:mm",
                                hour: "MM-DD HH:mm",
                            }
                        },
                        min: this.getXAxisMin(),
                        max: this.getXAxisMax(),
                        ticks: {
                            sampleSize: 3,
                            maxRotation: 0,
                            autoSkipPadding: 30,
                            padding: 3,
                        },
                        grid: {
                            color: this.$root.theme === "light" ? "rgba(0,0,0,0.1)" : "rgba(255,255,255,0.1)",
                            offset: false,
                        },
                    },
                    y: {
                        title: {
                            display: true,
                            text: this.$t("respTime"),
                        },
                        offset: false,
                        grid: {
                            color: this.$root.theme === "light" ? "rgba(0,0,0,0.1)" : "rgba(255,255,255,0.1)",
                        },
                    },
                    y1: {
                        display: false,
                        position: "right",
                        grid: {
                            drawOnChartArea: false,
                        },
                        min: 0,
                        max: 1,
                        offset: false,
                    },
                },
                bounds: "ticks",
                plugins: {
                    tooltip: {
                        mode: "nearest",
                        intersect: false,
                        padding: 10,
                        backgroundColor: this.$root.theme === "light" ? "rgba(212,232,222,1.0)" : "rgba(32,42,38,1.0)",
                        bodyColor: this.$root.theme === "light" ? "rgba(12,12,18,1.0)" : "rgba(220,220,220,1.0)",
                        titleColor: this.$root.theme === "light" ? "rgba(12,12,18,1.0)" : "rgba(220,220,220,1.0)",
                        filter: function (tooltipItem) {
                            return tooltipItem.datasetIndex === 0;  // Hide tooltip on Bar Chart
                        },
                        callbacks: {
                            label: (context) => {
                                return ` ${new Intl.NumberFormat().format(context.parsed.y)} ms`;
                            },
                        }
                    },
                    legend: {
                        display: false,
                    },
                },
            };
        },
        chartData() {
            if (this.chartPeriodHrs === "0") {
                return this.getChartDatapointsFromHeartbeatList();
            } else {
                return this.getChartDatapointsFromStats();
            }
        },
    },
    watch: {
        // Update chart data when the selected chart period changes
        chartPeriodHrs: function (newPeriod) {
            if (this.chartDataFetchInterval) {
                clearInterval(this.chartDataFetchInterval);
                this.chartDataFetchInterval = null;
            }

            // eslint-disable-next-line eqeqeq
            if (newPeriod == "0") {
                this.heartbeatList = null;
                this.$root.storage()["chart-period"] = newPeriod;
                this.showDatePicker = false;
            } else if (newPeriod === "custom") {
                // Don't auto-show date picker, let user click the calendar icon
                // For custom range, wait for dateRange to be set
                if (this.dateRange && this.dateRange.length === 2 && this.dateRange[0] && this.dateRange[1]) {
                    this.applyCustomDateRange();
                }
            } else {
                this.showDatePicker = false;
                this.loading = true;

                let period;
                try {
                    period = parseInt(newPeriod);
                } catch (e) {
                    // Invalid period
                    period = 24;
                }

                this.fetchChartData(period);
            }
        }
    },
    created() {
        // Load chart period from storage if saved
        let period = this.$root.storage()["chart-period"];
        if (period != null) {
            // Has this ever been not a string?
            if (typeof period !== "string") {
                period = period.toString();
            }
            
            // Check if it's a custom period (format: "custom-{hours}")
            if (period.startsWith("custom-")) {
                const hours = parseInt(period.split("-")[1]);
                if (!isNaN(hours) && hours > 0) {
                    this.customPeriodHours = hours;
                    // Calculate date range from hours (end date is now, start date is hours ago)
                    const endDate = dayjs().toDate();
                    const startDate = dayjs().subtract(hours, 'hour').toDate();
                    this.dateRange = [startDate, endDate];
                    // Set chartPeriodHrs after dateRange is set so watch can trigger properly
                    this.$nextTick(() => {
                        this.chartPeriodHrs = "custom";
                    });
                } else {
                    this.chartPeriodHrs = "0";
                }
            } else {
                this.chartPeriodHrs = period;
            }
        } else {
            this.chartPeriodHrs = "0";
        }
    },
    mounted() {
        // Add click outside listener to close date picker
        document.addEventListener('click', this.handleClickOutside);
    },
    beforeUnmount() {
        if (this.chartDataFetchInterval) {
            clearInterval(this.chartDataFetchInterval);
        }
        // Remove click outside listener
        document.removeEventListener('click', this.handleClickOutside);
    },
    methods: {
        handlePeriodSelect(key) {
            this.chartPeriodHrs = key;
            // If selecting custom, automatically show date picker
            if (key === 'custom') {
                this.$nextTick(() => {
                    this.showDatePicker = true;
                });
            }
        },
        handleClickOutside(event) {
            if (this.showDatePicker && this.$refs.datePickerRef) {
                // Check if click is outside the date picker
                // Don't close if clicking on dropdown menu
                const target = event.target;
                const isClickOnDropdown = target.closest('.dropdown-menu') !== null;
                const isClickOnDropdownToggle = target.closest('.dropdown-toggle') !== null;
                
                if (!this.$refs.datePickerRef.contains(target) && 
                    !isClickOnDropdown && 
                    !isClickOnDropdownToggle) {
                    this.showDatePicker = false;
                }
            }
        },
        getXAxisMin() {
            if (this.chartPeriodHrs === "custom" && this.dateRange && this.dateRange.length === 2 && this.dateRange[0]) {
                return dayjs(this.dateRange[0]).startOf('day').toISOString();
            }
            return undefined;
        },
        getXAxisMax() {
            if (this.chartPeriodHrs === "custom" && this.dateRange && this.dateRange.length === 2 && this.dateRange[1]) {
                return dayjs(this.dateRange[1]).endOf('day').toISOString();
            }
            return undefined;
        },
        getDisplayPeriodText() {
            if (this.chartPeriodHrs === "custom") {
                if (this.dateRange && this.dateRange.length === 2 && this.dateRange[0] && this.dateRange[1]) {
                    const start = dayjs(this.dateRange[0]).format("YYYY-MM-DD");
                    const end = dayjs(this.dateRange[1]).format("YYYY-MM-DD");
                    return `${start} ~ ${end}`;
                }
                return this.chartPeriodOptions["custom"];
            }
            return this.chartPeriodOptions[this.chartPeriodHrs] || this.chartPeriodOptions[0];
        },
        applyCustomDateRange() {
            if (!this.dateRange || this.dateRange.length !== 2 || !this.dateRange[0] || !this.dateRange[1]) {
                return;
            }

            const startDate = dayjs(this.dateRange[0]);
            const endDate = dayjs(this.dateRange[1]);
            
            // Calculate hours between start and end date
            const hours = endDate.diff(startDate, 'hour');
            
            if (hours <= 0) {
                this.$root.toastError(this.$t("Invalid date range. End date must be after start date.") || "Invalid date range. End date must be after start date.");
                return;
            }

            this.customPeriodHours = hours;
            this.loading = true;
            this.fetchChartData(hours);
            
            // Hide date picker after selection
            this.$nextTick(() => {
                this.showDatePicker = false;
            });
        },
        fetchChartData(period) {
            this.$root.getMonitorChartData(this.monitorId, period, (res) => {
                if (!res.ok) {
                    this.$root.toastError(res.msg);
                } else {
                    this.chartRawData = res.data;
                    const periodKey = this.chartPeriodHrs === "custom" ? `custom-${this.customPeriodHours}` : this.chartPeriodHrs;
                    this.$root.storage()["chart-period"] = periodKey;
                }
                this.loading = false;
            });

            this.chartDataFetchInterval = setInterval(() => {
                this.$root.getMonitorChartData(this.monitorId, period, (res) => {
                    if (res.ok) {
                        this.chartRawData = res.data;
                    }
                });
            }, 5 * 60 * 1000);
        },
        // Get color of bar chart for this datapoint
        getBarColorForDatapoint(datapoint) {
            if (datapoint.maintenance != null) {
                // Target is in maintenance
                return "rgba(23,71,245,0.41)";
            } else if (datapoint.down === 0) {
                // Target is up, no need to display a bar
                return "#000";
            } else if (datapoint.up === 0) {
                // Target is down
                return "rgba(220, 53, 69, 0.41)";
            } else {
                // Show yellow for mixed status
                return "rgba(245, 182, 23, 0.41)";
            }
        },
        // push datapoint to chartData
        pushDatapoint(datapoint, avgPingData, minPingData, maxPingData, downData, colorData) {
            const x = this.$root.unixToDateTime(datapoint.timestamp);

            // Show ping values if it was up in this period
            avgPingData.push({
                x,
                y: datapoint.up > 0 && datapoint.avgPing > 0 ? datapoint.avgPing : null,
            });
            minPingData.push({
                x,
                y: datapoint.up > 0 && datapoint.avgPing > 0 ? datapoint.minPing : null,
            });
            maxPingData.push({
                x,
                y: datapoint.up > 0 && datapoint.avgPing > 0 ? datapoint.maxPing : null,
            });
            downData.push({
                x,
                y: datapoint.down + (datapoint.maintenance || 0),
            });

            colorData.push(this.getBarColorForDatapoint(datapoint));
        },
        // get the average of a set of datapoints
        getAverage(datapoints) {
            const totalUp = datapoints.reduce((total, current) => total + current.up, 0);
            const totalDown = datapoints.reduce((total, current) => total + current.down, 0);
            const totalMaintenance = datapoints.reduce((total, current) => total + (current.maintenance || 0), 0);
            const totalPing = datapoints.reduce((total, current) => total + current.avgPing * current.up, 0);
            const minPing = datapoints.reduce((min, current) => Math.min(min, current.minPing), Infinity);
            const maxPing = datapoints.reduce((max, current) => Math.max(max, current.maxPing), 0);

            // Find the middle timestamp to use
            let midpoint = Math.floor(datapoints.length / 2);

            return {
                timestamp: datapoints[midpoint].timestamp,
                up: totalUp,
                down: totalDown,
                maintenance: totalMaintenance > 0 ? totalMaintenance : undefined,
                avgPing: totalUp > 0 ? totalPing / totalUp : 0,
                minPing,
                maxPing,
            };
        },
        getChartDatapointsFromHeartbeatList() {
            // Render chart using heartbeatList
            let lastHeartbeatTime;
            const monitorInterval = this.$root.monitorList[this.monitorId]?.interval;
            let pingData = [];  // Ping Data for Line Chart, y-axis contains ping time
            let downData = [];  // Down Data for Bar Chart, y-axis is 1 if target is down (red color), under maintenance (blue color) or pending (orange color), 0 if target is up
            let colorData = []; // Color Data for Bar Chart

            let heartbeatList = (this.monitorId in this.$root.heartbeatList && this.$root.heartbeatList[this.monitorId]) || [];

            for (const beat of heartbeatList) {
                const beatTime = this.$root.toDayjs(beat.time);
                const x = beatTime.format("YYYY-MM-DD HH:mm:ss");

                // Insert empty datapoint to separate big gaps
                if (lastHeartbeatTime && monitorInterval) {
                    const diff = Math.abs(beatTime.diff(lastHeartbeatTime));
                    if (diff > monitorInterval * 1000 * 10) {
                        // Big gap detected
                        const gapX = [
                            lastHeartbeatTime.add(monitorInterval, "second").format("YYYY-MM-DD HH:mm:ss"),
                            beatTime.subtract(monitorInterval, "second").format("YYYY-MM-DD HH:mm:ss")
                        ];

                        for (const x of gapX) {
                            pingData.push({
                                x,
                                y: null,
                            });
                            downData.push({
                                x,
                                y: null,
                            });
                            colorData.push("#000");
                        }

                    }
                }

                pingData.push({
                    x,
                    y: beat.status === UP ? beat.ping : null,
                });
                downData.push({
                    x,
                    y: (beat.status === DOWN || beat.status === MAINTENANCE || beat.status === PENDING) ? 1 : 0,
                });
                switch (beat.status) {
                    case MAINTENANCE:
                        colorData.push("rgba(23 ,71, 245, 0.41)");
                        break;
                    case PENDING:
                        colorData.push("rgba(245, 182, 23, 0.41)");
                        break;
                    default:
                        colorData.push("rgba(220, 53, 69, 0.41)");
                }

                lastHeartbeatTime = beatTime;
            }

            return {
                datasets: [
                    {
                        // Line Chart
                        data: pingData,
                        fill: "origin",
                        tension: 0.2,
                        borderColor: "#5CDD8B",
                        backgroundColor: "#5CDD8B38",
                        yAxisID: "y",
                        label: "ping",
                    },
                    {
                        // Bar Chart
                        type: "bar",
                        data: downData,
                        borderColor: "#00000000",
                        backgroundColor: colorData,
                        yAxisID: "y1",
                        barThickness: "flex",
                        barPercentage: 1,
                        categoryPercentage: 1,
                        inflateAmount: 0.05,
                        label: "status",
                    },
                ],
            };
        },
        getChartDatapointsFromStats() {
            // Render chart using UptimeCalculator data
            let lastHeartbeatTime;
            const monitorInterval = this.$root.monitorList[this.monitorId]?.interval;

            let avgPingData = [];  // Ping Data for Line Chart, y-axis contains ping time
            let minPingData = [];  // Ping Data for Line Chart, y-axis contains ping time
            let maxPingData = [];  // Ping Data for Line Chart, y-axis contains ping time
            let downData = [];  // Down Data for Bar Chart, y-axis is number of down datapoints in this period
            let colorData = []; // Color Data for Bar Chart

            const period = this.chartPeriodHrs === "custom" ? this.customPeriodHours : parseInt(this.chartPeriodHrs);
            let aggregatePoints = period > 6 ? 12 : 4;

            let aggregateBuffer = [];

            if (this.chartRawData) {
                for (const datapoint of this.chartRawData) {
                    const beatTime = this.$root.unixToDayjs(datapoint.timestamp);
                    
                    // Even if datapoint is empty, we still want to show it on the chart
                    // This ensures the chart displays the full time range even with sparse data
                    const isEmpty = datapoint.up === 0 && datapoint.down === 0 && datapoint.maintenance === 0;

                    // Insert empty datapoint to separate big gaps
                    if (lastHeartbeatTime && monitorInterval) {
                        const diff = Math.abs(beatTime.diff(lastHeartbeatTime));
                        const oneSecond = 1000;
                        const oneMinute = oneSecond * 60;
                        const oneHour = oneMinute * 60;
                        if ((period <= 24 && diff > Math.max(oneMinute * 10, monitorInterval * oneSecond * 10)) ||
                            (period > 24 && diff > Math.max(oneHour * 10, monitorInterval * oneSecond * 10))) {
                            // Big gap detected
                            // Clear the aggregate buffer
                            if (aggregateBuffer.length > 0) {
                                const average = this.getAverage(aggregateBuffer);
                                this.pushDatapoint(average, avgPingData, minPingData, maxPingData, downData, colorData);
                                aggregateBuffer = [];
                            }

                            const gapX = [
                                lastHeartbeatTime.subtract(monitorInterval, "second").format("YYYY-MM-DD HH:mm:ss"),
                                this.$root.unixToDateTime(datapoint.timestamp + 60),
                            ];

                            for (const x of gapX) {
                                avgPingData.push({
                                    x,
                                    y: null,
                                });
                                minPingData.push({
                                    x,
                                    y: null,
                                });
                                maxPingData.push({
                                    x,
                                    y: null,
                                });
                                downData.push({
                                    x,
                                    y: null,
                                });
                                colorData.push("#000");
                            }

                        }
                    }

                    if (isEmpty) {
                        // Even for empty datapoints, we still want to show them on the chart
                        // This ensures the chart displays the full time range even with sparse data
                        // Clear the aggregate buffer first
                        if (aggregateBuffer.length > 0) {
                            const average = this.getAverage(aggregateBuffer);
                            this.pushDatapoint(average, avgPingData, minPingData, maxPingData, downData, colorData);
                            aggregateBuffer = [];
                        }
                        // Push empty datapoint (all values will be null/0)
                        this.pushDatapoint(datapoint, avgPingData, minPingData, maxPingData, downData, colorData);
                    } else if (datapoint.up > 0 && this.chartRawData.length > aggregatePoints * 2) {
                        // Aggregate Up data using a sliding window
                        aggregateBuffer.push(datapoint);

                        if (aggregateBuffer.length === aggregatePoints) {
                            const average = this.getAverage(aggregateBuffer);
                            this.pushDatapoint(average, avgPingData, minPingData, maxPingData, downData, colorData);
                            // Remove the first half of the buffer
                            aggregateBuffer = aggregateBuffer.slice(Math.floor(aggregatePoints / 2));
                        }
                    } else {
                        // datapoint is fully down or too few datapoints, no need to aggregate
                        // Clear the aggregate buffer
                        if (aggregateBuffer.length > 0) {
                            const average = this.getAverage(aggregateBuffer);
                            this.pushDatapoint(average, avgPingData, minPingData, maxPingData, downData, colorData);
                            aggregateBuffer = [];
                        }

                        this.pushDatapoint(datapoint, avgPingData, minPingData, maxPingData, downData, colorData);
                    }

                    lastHeartbeatTime = beatTime;
                }
                // Clear the aggregate buffer if there are still datapoints
                if (aggregateBuffer.length > 0) {
                    const average = this.getAverage(aggregateBuffer);
                    this.pushDatapoint(average, avgPingData, minPingData, maxPingData, downData, colorData);
                    aggregateBuffer = [];
                }
            } else {
                // Even if there's no data, we should still show the chart with the time range
                // This ensures the x-axis displays correctly for the selected period
                // The chart will show as empty but with proper time axis
            }

            return {
                datasets: [
                    {
                        // average ping chart
                        data: avgPingData,
                        fill: "origin",
                        tension: 0.2,
                        borderColor: "#5CDD8B",
                        backgroundColor: "#5CDD8B06",
                        yAxisID: "y",
                        label: "avg-ping",
                    },
                    {
                        // minimum ping chart
                        data: minPingData,
                        fill: "origin",
                        tension: 0.2,
                        borderColor: "#3CBD6B38",
                        backgroundColor: "#5CDD8B06",
                        yAxisID: "y",
                        label: "min-ping",
                    },
                    {
                        // maximum ping chart
                        data: maxPingData,
                        fill: "origin",
                        tension: 0.2,
                        borderColor: "#7CBD6B38",
                        backgroundColor: "#5CDD8B06",
                        yAxisID: "y",
                        label: "max-ping",
                    },
                    {
                        // Bar Chart
                        type: "bar",
                        data: downData,
                        borderColor: "#00000000",
                        backgroundColor: colorData,
                        yAxisID: "y1",
                        barThickness: "flex",
                        barPercentage: 1,
                        categoryPercentage: 1,
                        inflateAmount: 0.05,
                        label: "status",
                    },
                ],
            };
        },
    }
};
</script>

<style lang="scss" scoped>
@import "../assets/vars.scss";

.form-select {
    width: unset;
    display: inline-flex;
}

.period-options {
    padding: 0.1em 1em;
    margin-bottom: -1.2em;
    float: right;
    position: relative;
    z-index: 10;

    .custom-date-range {
        position: absolute;
        top: 100%;
        right: 0;
        margin-top: 0.5em;
        z-index: 1000;
        background: var(--bs-body-bg, #fff);
        padding: 1.5em;
        border-radius: 0.5rem;
        box-shadow: 0 0.25rem 0.75rem rgba(0, 0, 0, 0.2), 0 0.5rem 1.5rem rgba(0, 0, 0, 0.15);
        min-width: 350px;
        max-width: 450px;
        border: 1px solid rgba(0, 0, 0, 0.1);

        .dark & {
            background: $dark-bg;
            border-color: rgba(255, 255, 255, 0.1);
        }

        h6 {
            color: var(--bs-body-color);
            font-weight: 600;
        }

        .btn-close {
            opacity: 0.6;
            font-size: 1.1em;
            
            &:hover {
                opacity: 1;
            }
        }

        small {
            display: block;
            padding: 0.5em;
            background: rgba(92, 221, 139, 0.1);
            border-radius: 0.25rem;
        }
    }

    .btn-date-range-toggle {
        font-size: 0.85em;
        padding: 4px 12px;
        white-space: nowrap;
        
        &:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
    }

    .dropdown-menu {
        padding: 0;
        min-width: 50px;
        font-size: 0.9em;

        .dark & {
            background: $dark-bg;
        }

        .dropdown-item {
            border-radius: 0.3rem;
            padding: 2px 16px 4px;

            .dark & {
                background: $dark-bg;
                color: $dark-font-color;
            }

            .dark &:hover {
                background: $dark-font-color;
                color: $dark-font-color2;
            }
        }

        .dark & .dropdown-item.active {
            background: $primary;
            color: $dark-font-color2;
        }
    }

    .btn-period-toggle {
        padding: 2px 15px;
        background: transparent;
        border: 0;
        color: $link-color;
        opacity: 0.7;
        font-size: 0.9em;

        &::after {
            vertical-align: 0.155em;
        }

        .dark & {
            color: $dark-font-color;
        }
    }

    .btn-calendar-toggle {
        padding: 2px 8px;
        font-size: 0.85em;
        opacity: 0.7;
        
        &:hover {
            opacity: 1;
        }
    }
}

.chart-wrapper {
    margin-bottom: 0.5em;

    &.loading {
        filter: blur(10px);
    }
}
</style>
