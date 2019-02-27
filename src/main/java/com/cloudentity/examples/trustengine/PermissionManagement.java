package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.permissions.client.ApiClient;
import com.cloudentity.libs.permissions.client.api.PermissionsApi;
import com.cloudentity.libs.permissions.client.model.*;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static com.cloudentity.examples.trustengine.config.Credentials.*;
import static com.cloudentity.examples.trustengine.helpers.Commons.*;
import static java.util.Optional.*;

public class PermissionManagement {

  private static Logger log = LoggerFactory.getLogger(FineGrainedPermissionsValidation.class);

  private static ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  protected static PermissionsApi permissionsServiceClient = client.buildClient(PermissionsApi.class);

  public static void main(String[] args) {
    try {
      log.info("Permissions for application: {}", listApplicationPermissions());

      log.info("Let's create some permission: {}", fineGrainedPermissionName);
      createPermissionForApplication(fineGrainedPermissionName);

      log.info("and also: {}", rbacPermissionName);
      createPermissionForApplication(rbacPermissionName);

      log.info("Now let's verify that permissions {} and {} was added", fineGrainedPermissionName, rbacPermissionName);
      log.info("Permissions for application: {}", listApplicationPermissions());

      log.info("Let's verify what permissions are assigned to the user: {}", userUuid);
      List<PermissionGrant> grants = listPermissionsForUser(userUuid);
      log.info("List all user permissions for user {} for application: {}", userUuid, grants);

      if (grants.isEmpty()) {
        log.info("There are no permissions assigned to user");
      } else {
        log.info("Found permissions for user {}. Removing...", userUuid);
        grants.forEach(PermissionManagement::revokePermissionForUser);
        log.info("All grants removed. Permissions for user after removal: {}", listPermissionsForUser(userUuid));
      }

      log.info("Let's grant coarse-grained (for RBAC) permission: {} to user {}", rbacPermissionName, userUuid);
      grantPermissionToUser(rbacPermissionName, userUuid);

      log.info("Now user permissions for user {} for application: {}", userUuid, listPermissionsForUser(userUuid));

      log.info("Now let's grant fine-grained permission {} to user {} for file {}", fineGrainedPermissionName, userUuid, fileName);
      grantPermissionToUserForFile(fineGrainedPermissionName, userUuid, fileName);

      log.info("Now user permissions for user {} for application: {}", userUuid, listPermissionsForUser(userUuid));
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }

  private static void grantPermissionToUserForFile(String permissionName, String userUuid, String fileName) {
    grantPermission(permissionName, userPrefix + ":" + userUuid, Optional.of(filePrefix + ":" + fileName));
  }

  private static void grantPermissionToUser(String permissionName, String userUuid) {
    grantPermission(permissionName, userPrefix + ":" + userUuid, empty());
  }

  private static void grantPermission(String permissionName, String principal, Optional<String> object) {
    ApplicationPermissionGrantSet permissionGrant = new ApplicationPermissionGrantSet();
    permissionGrant.setName(permissionName);
    permissionGrant.setPrincipal(principal);
    object.ifPresent(o -> permissionGrant.setObject(o));
    permissionsServiceClient.applicationSetPermissionGrant(permissionGrant);
  }

  private static List<PermissionGrant> listPermissionsForUser(String userUuid) {
    return permissionsServiceClient.applicationListAllPermissionGrantsByPrincipal(userPrefix, userUuid);
  }

  private static void createPermissionForApplication(String permissionName) {
    SetPermission permission = new SetPermission();
    permission.setName(permissionName);
    permissionsServiceClient.applicationSetPermission(permission);
  }

  private static List<Permission> listApplicationPermissions() {
    return permissionsServiceClient.applicationListPermissions();
  }

  private static void revokePermissionForUser(PermissionGrant g) {
    ApplicationPermissionGrantDelete applicationPermissionGrantDelete = new ApplicationPermissionGrantDelete();
    applicationPermissionGrantDelete.setName(g.getPermissionKey().getName());
    applicationPermissionGrantDelete.setObject(g.getObject());
    applicationPermissionGrantDelete.setPrincipal(g.getPrincipal());
    permissionsServiceClient.applicationDeleteGrant(applicationPermissionGrantDelete);
  }
}
