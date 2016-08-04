import json
from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase

class GroupsTest(BaseTestCase):

    def setUp(self):
        self.user_name = self.user.username
        self.admin_name = self.admin.username

    def tearDown(self):
        self.remove_group()

    def test_can_get(self):
        self.login_as(self.admin)
        url = reverse('api-v2.1-admin-groups')
        resp = self.client.get(url)

        json_resp = json.loads(resp.content)
        assert len(json_resp['groups']) > 0

    def test_get_with_invalid_user_permission(self):
        self.login_as(self.user)
        url = reverse('api-v2.1-admin-groups')
        resp = self.client.get(url)
        self.assertEqual(403, resp.status_code)

class GroupTest(BaseTestCase):

    def setUp(self):
        self.user_name = self.user.username
        self.admin_name = self.admin.username
        self.group_id = self.group.id

    def test_can_transfer_group(self):

        self.login_as(self.admin)

        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        data = 'new_owner=%s' % self.admin_name
        resp = self.client.put(url, data, 'application/x-www-form-urlencoded')

        self.assertEqual(200, resp.status_code)
        json_resp = json.loads(resp.content)
        assert json_resp['owner'] == self.admin_name

    def test_transfer_group_invalid_user_permission(self):

        self.login_as(self.user)

        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        data = 'new_owner=%s' % self.admin_name
        resp = self.client.put(url, data, 'application/x-www-form-urlencoded')

        self.assertEqual(403, resp.status_code)

    def test_transfer_group_invalid_args(self):

        self.login_as(self.admin)

        # invalid new owner
        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        data = 'invalid_new_owner=%s' % self.admin_name
        resp = self.client.put(url, data, 'application/x-www-form-urlencoded')
        self.assertEqual(400, resp.status_code)

        # new owner not exist
        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        data = 'new_owner=invalid@email.com'
        resp = self.client.put(url, data, 'application/x-www-form-urlencoded')
        self.assertEqual(404, resp.status_code)

    def test_can_delete(self):
        self.login_as(self.admin)
        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        resp = self.client.delete(url)
        self.assertEqual(200, resp.status_code)

        json_resp = json.loads(resp.content)
        assert json_resp['success'] is True

    def test_delete_with_invalid_user_permission(self):
        self.login_as(self.user)
        url = reverse('api-v2.1-admin-group', args=[self.group_id])
        resp = self.client.delete(url)
        self.assertEqual(403, resp.status_code)
