import './console-bridge.js';
import './style.css';
import { installUiRefreshListener } from './ui-refresh.js';
import './components/toast.js';
import './components/dns-status.js';
import './components/dns-records.js';
import './components/http-status.js';
import './components/http-routes.js';
import './components/s3-status.js';
import './components/s3-buckets.js';
import './components/oidc-status.js';
import './components/oidc-clients.js';
import './components/wsl-instance.js';
import './components/k8s-client.js';

installUiRefreshListener();
