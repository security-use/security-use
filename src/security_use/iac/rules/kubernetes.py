"""Kubernetes security rules for IaC scanning."""

from security_use.models import Severity
from security_use.iac.base import IaCResource
from security_use.iac.rules.base import Rule, RuleResult


class K8sRunAsRootRule(Rule):
    """Check that containers don't run as root."""

    RULE_ID = "CKV_K8S_6"
    TITLE = "Container running as root"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Container is configured to run as root user. Running as root "
        "increases the risk of container breakout and privilege escalation."
    )
    REMEDIATION = (
        "Set securityContext.runAsNonRoot to true and specify a non-root runAsUser."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "kubernetes_stateful_set",
        "kubernetes_daemon_set",
        "kubernetes_job",
        "kubernetes_cron_job",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if container runs as root."""
        runs_as_root = False

        # Get pod spec - handle different resource types
        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        # Check pod-level security context
        pod_security = spec.get("securityContext", {})
        run_as_non_root = pod_security.get("runAsNonRoot", False)
        run_as_user = pod_security.get("runAsUser")

        # If pod-level says non-root, we're good
        if run_as_non_root or (run_as_user is not None and run_as_user != 0):
            return self._create_result(True, resource)

        # Check container-level security context
        containers = spec.get("containers", [])
        for container in containers:
            container_security = container.get("securityContext", {})
            container_run_as_user = container_security.get("runAsUser")
            container_run_as_non_root = container_security.get("runAsNonRoot", False)

            if container_run_as_user == 0:
                runs_as_root = True
                break

            if not container_run_as_non_root and run_as_user is None and container_run_as_user is None:
                runs_as_root = True
                break

        fix_code = None
        if runs_as_root:
            fix_code = '''securityContext:
  runAsNonRoot: true
  runAsUser: 1000'''

        return self._create_result(not runs_as_root, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config

        # Direct pod
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]

        # Deployment/StatefulSet/etc with template
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]

        # Terraform kubernetes_pod
        pod_spec = config.get("spec", [{}])
        if isinstance(pod_spec, list) and pod_spec:
            return pod_spec[0]

        return {}


class K8sPrivilegedContainerRule(Rule):
    """Check that containers don't run in privileged mode."""

    RULE_ID = "CKV_K8S_1"
    TITLE = "Privileged container"
    SEVERITY = Severity.CRITICAL
    DESCRIPTION = (
        "Container is running in privileged mode. Privileged containers have "
        "full access to the host and can escape container isolation."
    )
    REMEDIATION = (
        "Set securityContext.privileged to false."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if container runs privileged."""
        is_privileged = False

        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        containers = spec.get("containers", [])
        for container in containers:
            security = container.get("securityContext", {})
            if security.get("privileged", False):
                is_privileged = True
                break

        fix_code = None
        if is_privileged:
            fix_code = '''securityContext:
  privileged: false'''

        return self._create_result(not is_privileged, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]
        return {}


class K8sResourceLimitsRule(Rule):
    """Check that containers have resource limits defined."""

    RULE_ID = "CKV_K8S_11"
    TITLE = "Container without resource limits"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Container does not have resource limits defined. Without limits, "
        "a container can consume all available resources on the node."
    )
    REMEDIATION = (
        "Define resources.limits for CPU and memory."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if container has resource limits."""
        has_limits = True

        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        containers = spec.get("containers", [])
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get("limits", {})

            if not limits.get("cpu") or not limits.get("memory"):
                has_limits = False
                break

        fix_code = None
        if not has_limits:
            fix_code = '''resources:
  limits:
    cpu: "500m"
    memory: "512Mi"
  requests:
    cpu: "100m"
    memory: "128Mi"'''

        return self._create_result(has_limits, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]
        return {}


class K8sHostNetworkRule(Rule):
    """Check that pods don't use host network namespace."""

    RULE_ID = "CKV_K8S_19"
    TITLE = "Pod using host network"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Pod is configured to use the host network namespace. This allows "
        "the container to access all network interfaces on the host."
    )
    REMEDIATION = (
        "Set hostNetwork to false unless absolutely necessary."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if pod uses host network."""
        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        host_network = spec.get("hostNetwork", False)

        fix_code = None
        if host_network:
            fix_code = "hostNetwork: false"

        return self._create_result(not host_network, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]
        return {}


class K8sSecretsEnvVarsRule(Rule):
    """Check that secrets are not exposed as environment variables."""

    RULE_ID = "CKV_K8S_35"
    TITLE = "Secrets exposed as environment variables"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Secrets are exposed as environment variables. Environment variables "
        "can be logged or exposed through process listings. Use volume mounts instead."
    )
    REMEDIATION = (
        "Mount secrets as volumes instead of using envFrom with secretRef."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if secrets are exposed as env vars."""
        secrets_in_env = False

        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        containers = spec.get("containers", [])
        for container in containers:
            # Check envFrom with secretRef
            env_from = container.get("envFrom", [])
            for env in env_from:
                if "secretRef" in env:
                    secrets_in_env = True
                    break

            # Check individual env vars with secretKeyRef
            env_vars = container.get("env", [])
            for env in env_vars:
                value_from = env.get("valueFrom", {})
                if "secretKeyRef" in value_from:
                    secrets_in_env = True
                    break

            if secrets_in_env:
                break

        fix_code = None
        if secrets_in_env:
            fix_code = '''# Mount secrets as volumes instead
volumeMounts:
  - name: secret-volume
    mountPath: "/etc/secrets"
    readOnly: true
volumes:
  - name: secret-volume
    secret:
      secretName: my-secret'''

        return self._create_result(not secrets_in_env, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]
        return {}


class K8sReadOnlyRootFilesystemRule(Rule):
    """Check that containers use read-only root filesystem."""

    RULE_ID = "CKV_K8S_22"
    TITLE = "Container without read-only root filesystem"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Container does not have a read-only root filesystem. A read-only "
        "filesystem prevents malicious writes to the container filesystem."
    )
    REMEDIATION = (
        "Set securityContext.readOnlyRootFilesystem to true."
    )
    RESOURCE_TYPES = [
        "kubernetes_pod",
        "kubernetes_deployment",
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if container has read-only root filesystem."""
        has_readonly = True

        spec = self._get_pod_spec(resource)
        if not spec:
            return self._create_result(True, resource)

        containers = spec.get("containers", [])
        for container in containers:
            security = container.get("securityContext", {})
            if not security.get("readOnlyRootFilesystem", False):
                has_readonly = False
                break

        fix_code = None
        if not has_readonly:
            fix_code = '''securityContext:
  readOnlyRootFilesystem: true'''

        return self._create_result(has_readonly, resource, fix_code)

    def _get_pod_spec(self, resource: IaCResource) -> dict:
        """Extract pod spec from various resource types."""
        config = resource.config
        if "spec" in config and "containers" in config.get("spec", {}):
            return config["spec"]
        spec = config.get("spec", {})
        template = spec.get("template", {})
        if "spec" in template:
            return template["spec"]
        return {}


class K8sNetworkPolicyRule(Rule):
    """Check that namespaces have network policies defined."""

    RULE_ID = "CKV_K8S_24"
    TITLE = "Missing network policy"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "No network policy is defined for this namespace. Without network "
        "policies, all pods can communicate with each other by default."
    )
    REMEDIATION = (
        "Define NetworkPolicy resources to restrict pod-to-pod communication."
    )
    RESOURCE_TYPES = ["kubernetes_namespace", "Namespace"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Flag namespaces that should have network policies."""
        # This is a best-effort check - we can't verify NetworkPolicy exists
        # from the namespace resource alone

        fix_code = '''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress'''

        # Default to warning to encourage network policies
        return self._create_result(False, resource, fix_code)
