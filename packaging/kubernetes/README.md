# Datadog Process Agent in Kubernetes

This allows you to run the dd-process-agent _and_ the infrastructure dd-agent in a Kubernetes cluster. These will run together in a single container so there's no need to run a dd-agent Daemonset separately.

## Quick Start

You can take advantage of Kuberentes DaemonSets to automatically deploy the Datadog Agent and Process Agent on all your nodes (or on specific nodes by using `nodeSelectors`). We include a sample file at [dd-process-agent.yml](dd-process-agent.yml) to get you started.

1. Modify the API key in `dd-process-agent.yml` to match your Datadog API key from [https://app.datadoghq.com/account/settings#api](https://app.datadoghq.com/account/settings#api)

2. (optional) Modify any other settings in the yml file, such as `nodeSelectors`, if you prefer to have greater control over the deployment.

3. Create the Daemonset and get the Agent running in the cluster:

    ```
    kubectl create -f dd-process-agent.yml
    ```

...and that's it! You should see the Agent pod running with `kubectl get daemonsets`.

For further configuration of Agent checks read our [detailed documentation](http://docs.datadoghq.com/integrations/kubernetes/) on running and configuring the dd-agent in Kubernetes.

