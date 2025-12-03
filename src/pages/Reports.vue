<template>
    <div class="container-fluid">
        <h1 class="mb-3">{{ $t("Reports") }}</h1>

        <div class="card mb-3">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <label class="form-label">{{ $t("Date Range") }}</label>
                        <Datepicker v-model="dateRange" range :enableTimePicker="false" />
                    </div>
                    <div class="col-md-8 d-flex align-items-end mb-3">
                        <button class="btn btn-primary me-2" @click="fetchStats" :disabled="loading">
                            <font-awesome-icon icon="sync" v-if="!loading" />
                            <font-awesome-icon icon="spinner" spin v-else />
                            {{ $t("Generate Preview") }}
                        </button>
                        <button class="btn btn-success me-2" @click="exportCSV" :disabled="loading">
                            <font-awesome-icon icon="file-csv" /> {{ $t("Export CSV") }}
                        </button>

                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" v-if="stats.length > 0">
            <div class="col-md-6">
                <div class="card h-100">
                    <div class="card-header">{{ $t("Average Response Time") }}</div>
                    <div class="card-body">
                        <Bar :data="barChartData" :options="chartOptions" />
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card h-100">
                    <div class="card-header">{{ $t("Overall Uptime") }}</div>
                    <div class="card-body" style="position: relative; height: 300px;">
                         <Pie :data="pieChartData" :options="pieOptions" />
                    </div>
                </div>
            </div>
        </div>

        <div class="card" v-if="stats.length > 0">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>{{ $t("Monitor") }}</th>
                                <th>{{ $t("Uptime") }}</th>
                                <th>{{ $t("Downtime Count") }}</th>
                                <th>{{ $t("Avg Ping") }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="stat in stats" :key="stat.monitorId">
                                <td>{{ stat.name }}</td>
                                <td>
                                    <span class="badge bg-success" v-if="stat.uptimePercent >= 99">{{ stat.uptimePercent }}%</span>
                                    <span class="badge bg-warning" v-else-if="stat.uptimePercent >= 95">{{ stat.uptimePercent }}%</span>
                                    <span class="badge bg-danger" v-else>{{ stat.uptimePercent }}%</span>
                                </td>
                                <td>{{ stat.downtimeCount }}</td>
                                <td>{{ stat.avgPing }} ms</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="alert alert-info" v-else-if="!loading && searched">
            {{ $t("No data found for the selected period.") }}
        </div>
    </div>
</template>

<script>
import Datepicker from '@vuepic/vue-datepicker';
import '@vuepic/vue-datepicker/dist/main.css';
import axios from "axios";
import dayjs from "dayjs";
import { useToast } from "vue-toastification";
import {
  Chart as ChartJS,
  Title,
  Tooltip,
  Legend,
  BarElement,
  ArcElement,
  CategoryScale,
  LinearScale
} from 'chart.js'
import { Bar, Pie } from 'vue-chartjs'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend)

export default {
    components: { Datepicker, Bar, Pie },
    data() {
        return {
            dateRange: [dayjs().subtract(30, 'day').toDate(), dayjs().toDate()],
            stats: [],
            loading: false,
            searched: false,
            chartOptions: {
                responsive: true,
                maintainAspectRatio: false,
            },
            pieOptions: {
                responsive: true,
                maintainAspectRatio: false,
            }
        }
    },
    computed: {
        barChartData() {
            return {
                labels: this.stats.map(s => s.name),
                datasets: [{
                    label: 'Avg Ping (ms)',
                    backgroundColor: '#5CDD8B',
                    data: this.stats.map(s => s.avgPing)
                }]
            }
        },
        pieChartData() {
            // Aggregate total up vs down (approximate based on uptime %)
            // Since we don't have raw counts in the stats object for total pings, 
            // we can visualize the distribution of monitors by status or just use the avg uptime.
            // Better approach for Pie: Distribution of Monitors by Uptime Health
            
            let healthy = 0;
            let warning = 0;
            let down = 0;

            this.stats.forEach(s => {
                if (s.uptimePercent >= 99) healthy++;
                else if (s.uptimePercent >= 95) warning++;
                else down++;
            });

            return {
                labels: ['Healthy (>=99%)', 'Warning (95-99%)', 'Critical (<95%)'],
                datasets: [{
                    backgroundColor: ['#5CDD8B', '#F5B617', '#DC3545'],
                    data: [healthy, warning, down]
                }]
            }
        }
    },
    methods: {
        getParams() {
            const startDate = dayjs(this.dateRange[0]).startOf('day').toISOString();
            const endDate = dayjs(this.dateRange[1]).endOf('day').toISOString();
            return { startDate, endDate };
        },
        async fetchStats() {
            this.loading = true;
            this.searched = true;
            try {
                const token = localStorage.getItem("token");
                const headers = token ? { "Authorization": `Bearer ${token}` } : {};
                const res = await axios.get("/api/reports/stats", { 
                    params: this.getParams(),
                    headers: headers
                });
                if (res.data.ok) {
                    this.stats = res.data.stats;
                } else {
                    useToast().error(res.data.msg);
                }
            } catch (error) {
                useToast().error(error.message);
            } finally {
                this.loading = false;
            }
        },
        async exportCSV() {
            this.loading = true;
            try {
                const { startDate, endDate } = this.getParams();
                const token = localStorage.getItem("token");
                const headers = token ? { "Authorization": `Bearer ${token}` } : {};
                
                const response = await axios.get("/api/reports/export/csv", {
                    params: { startDate, endDate },
                    headers: headers,
                    responseType: 'blob',
                });
                
                const url = window.URL.createObjectURL(new Blob([response.data]));
                const link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', `uptime_report_${dayjs().format("YYYY-MM-DD")}.csv`);
                document.body.appendChild(link);
                link.click();
                link.remove();
            } catch (error) {
                useToast().error("Export failed: " + error.message);
            } finally {
                this.loading = false;
            }
        },

    },
    mounted() {
        this.fetchStats();
    }
}
</script>

<style scoped>
.container-fluid {
    width: 98%;
    padding-top: 20px;
}
</style>
