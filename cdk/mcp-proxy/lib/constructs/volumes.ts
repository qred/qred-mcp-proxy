import * as ecs from 'aws-cdk-lib/aws-ecs';

function setupVolume(volumeName: string, taskDefinition: ecs.TaskDefinition, mountConfigs: Array<{
  container: ecs.ContainerDefinition;
  readOnly: boolean;
  containerPath: string;
}>): void {
  taskDefinition.addVolume({
    name: volumeName,
    host: {}
  });

  mountConfigs.forEach(config => {
    config.container.addMountPoints({
      readOnly: config.readOnly,
      sourceVolume: volumeName,
      containerPath: config.containerPath
    });
  });
};

export function setupVolumes(
  taskDefinition: ecs.TaskDefinition,
): void {
  const configContainer = taskDefinition.findContainer('config-sync');
  const grafanaSidecarContainer = taskDefinition.findContainer('grafana');
  const proxyContainer = taskDefinition.findContainer('proxy');
  const authContainer = taskDefinition.findContainer('auth');

  // Since we need some of the init containers to set up the proxy container we add some dependencies
  if (proxyContainer) {
    // Config volume setup
    if (configContainer) {
      const configMounts = [
        { container: proxyContainer, readOnly: true, containerPath: '/app/config-sync' },
        { container: configContainer, readOnly: false, containerPath: '/shared' }
      ];
      if (authContainer) {
        configMounts.push({ container: authContainer, readOnly: true, containerPath: '/app/config-sync' });
      }
      setupVolume('config', taskDefinition, configMounts);

      // Proxy depends on config-sync completing
      proxyContainer.addContainerDependencies({
        container: configContainer,
        condition: ecs.ContainerDependencyCondition.COMPLETE
      });
    }

    // Grafana dependency condition
    if (grafanaSidecarContainer) {
      proxyContainer.addContainerDependencies({
        container: grafanaSidecarContainer,
        condition: ecs.ContainerDependencyCondition.START
      });
    }

    if (authContainer) {
      proxyContainer.addContainerDependencies({
        container: authContainer,
        condition: ecs.ContainerDependencyCondition.HEALTHY
      });
    }
  }
}
