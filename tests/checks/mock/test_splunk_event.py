# stdlib
import json

from utils.splunk import time_to_seconds
from tests.checks.common import AgentCheckTest, Fixtures
from checks import CheckException

def _mocked_saved_searches(*args, **kwargs):
    return []

class TestSplunkErrorResponse(AgentCheckTest):
    """
    Splunk event check should handle a FATAL message response
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:8089',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "error",
                        "parameters": {}
                    }],
                    'tags': []
                }
            ]
        }

        thrown = False
        try:
            self.run_check(config, mocks={
                '_dispatch_saved_search': _mocked_dispatch_saved_search,
                '_saved_searches': _mocked_saved_searches
            })
        except CheckException:
            thrown = True
        self.assertTrue(thrown, "Retrieving FATAL message from Splunk should throw.")

        self.assertEquals(self.service_checks[0]['status'], 2, "service check should have status AgentCheck.CRITICAL")


class TestSplunkEmptyEvents(AgentCheckTest):
    """
    Splunk event check should process empty response correctly
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {}
                    }]
                }
            ]
        }
        self.run_check(config, mocks={
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_minimal_search,
            '_saved_searches': _mocked_saved_searches
        })
        current_check_events = self.check.get_events()
        self.assertEqual(len(current_check_events), 0)

class TestSplunkMinimalEvents(AgentCheckTest):
    """
    Splunk event check should process minimal response correctly
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {}
                    }],
                    'tags': []
                }
            ]
        }

        self.run_check(config, mocks={
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_minimal_search,
            '_saved_searches': _mocked_saved_searches
        })

        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[0], {
            'event_type': None,
            'tags': [],
            'timestamp': 1488974400.0,
            'msg_title': None,
            'msg_text': None,
            'source_type_name': None
        })
        self.assertEqual(self.events[1], {
            'event_type': None,
            'tags': [],
            'timestamp': 1488974400.0,
            'msg_title': None,
            'msg_text': None,
            'source_type_name': None
        })


class TestSplunkFullEvents(AgentCheckTest):
    """
    Splunk event check should process full response correctly
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {}
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        self.run_check(config, mocks={
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_full_search,
            '_saved_searches': _mocked_saved_searches
        })

        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[0], {
            'event_type': "some_type",
            'timestamp': 1488997796.0,
            'msg_title': "some_title",
            'msg_text': "some_text",
            'source_type_name': 'unknown-too_small',
            'tags': [
                'from:grey',
                "full_formatted_message:Alarm 'Virtual machine CPU usage' on SWNC7R049 changed from Gray to Green",
                "alarm_name:Virtual machine CPU usage",
                "to:green",
                "key:19964908",
                "VMName:SWNC7R049",
                "checktag:checktagvalue"
            ]
        })

        self.assertEqual(self.events[1], {
            'event_type': "some_type",
            'timestamp': 1488997797.0,
            'msg_title': "some_title",
            'msg_text': "some_text",
            'source_type_name': 'unknown-too_small',
            'tags': [
                'from:grey',
                "full_formatted_message:Alarm 'Virtual machine memory usage' on SWNC7R049 changed from Gray to Green",
                "alarm_name:Virtual machine memory usage",
                "to:green",
                "key:19964909",
                "VMName:SWNC7R049",
                "checktag:checktagvalue"
            ]
        })


class TestSplunkEarliestTimeAndDuplicates(AgentCheckTest):
    """
    Splunk event check should poll batches responses
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "poll",
                        "parameters": {},
                        "batch_size": 2
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "expected_searches": ["poll"],
            "sid": "",
            "time": 0,
            "earliest_time": "",
            "throw": False
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_polling_search(*args, **kwargs):
            sid = args[0]
            count = args[1].batch_size
            return json.loads(Fixtures.read_file("batch_%s_seq_%s.json" % (sid, count)))

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            if test_data["throw"]:
                raise CheckException("Is broke it")

            class MockedResponse():
                def json(self):
                    return {"sid": test_data["sid"]}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])
            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_polling_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Initial run
        test_data["sid"] = "poll"
        test_data["time"] = time_to_seconds("2017-03-08T18:29:59.000000+0000")
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 4)
        self.assertEqual([e['event_type'] for e in self.events], ["0_1", "0_2", "1_1", "1_2"])

        # respect earliest_time
        test_data["sid"] = "poll1"
        test_data["earliest_time"] = '2017-03-08T18:29:59.000000+0000'
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 1)
        self.assertEqual([e['event_type'] for e in self.events], ["2_1"])

        # Throw exception during search
        test_data["throw"] = True
        thrown = False
        try:
            self.run_check(config, mocks=test_mocks)
        except CheckException:
            thrown = True
        self.assertTrue(thrown, "Expect thrown to be done from the mocked search")
        self.assertEquals(self.service_checks[0]['status'], 2, "service check should have status AgentCheck.CRITICAL")


class TestSplunkDelayFirstTime(AgentCheckTest):
    """
    Splunk event check should only start polling after the specified time
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {'default_initial_delay_seconds': 60},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {}
                    }],
                    'tags': []
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 1,
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        mocks = {
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_minimal_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Initial run
        self.run_check(config, mocks=mocks)
        self.assertEqual(len(self.events), 0)

        # Not polling yet
        test_data["time"] = 30
        self.run_check(config, mocks=mocks)
        self.assertEqual(len(self.events), 0)

        # Start polling
        test_data["time"] = 62
        self.run_check(config, mocks=mocks)
        self.assertEqual(len(self.events), 2)


class TestSplunkDeduplicateEventsInTheSameRun(AgentCheckTest):
    """
    Splunk event check should deduplicate events
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {"default_batch_size": 2},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "duplicates",
                        "parameters": {}
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "expected_searches": ["duplicates"],
            "sid": "",
            "time": 0,
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dup_search(*args, **kwargs):
            sid = args[0]
            count = args[1].batch_size
            return json.loads(Fixtures.read_file("batch_%s_seq_%s.json" % (sid, count)))

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": test_data["sid"]}
            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_dup_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Inital run
        test_data["sid"] = "no_dup"
        test_data["time"] = 1
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 2)
        self.assertEqual([e['event_type'] for e in self.events], ["1", "2"])


class TestSplunkContinueAfterRestart(AgentCheckTest):
    """
    Splunk event check should continue where it left off after restart
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {
                'default_max_restart_history_seconds': 86400,
                'default_max_query_time_range': 3600
            },
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "empty",
                        "parameters": {},
                        'max_restart_history_seconds': 86400,
                        'max_query_time_range': 3600
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 0,
            "earliest_time": "",
            "latest_time": None
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": "empty"}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])

            if test_data["latest_time"] is None:
                self.assertTrue('dispatch.latest_time' not in args[2])
            elif test_data["latest_time"] != "":
                self.assertEquals(args[2]['dispatch.latest_time'], test_data["latest_time"])

            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Initial run with initial time
        test_data["time"] = time_to_seconds('2017-03-08T00:00:00.000000+0000')
        test_data["earliest_time"] = '2017-03-08T00:00:00.000000+0000'
        test_data["latest_time"] = None
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 0)

        # Restart check and recover data
        test_data["time"] = time_to_seconds('2017-03-08T12:00:00.000000+0000')
        for slice_num in range(0, 11):
            test_data["earliest_time"] = '2017-03-08T%s:00:01.000000+0000' % (str(slice_num).zfill(2))
            test_data["latest_time"] = '2017-03-08T%s:00:01.000000+0000' % (str(slice_num + 1).zfill(2))
            self.run_check(config, mocks=test_mocks, force_reload=slice_num == 0)
            self.assertTrue(self.continue_after_commit, "As long as we are not done with history, the check should continue")

        # Now continue with real-time polling (earliest time taken from last event or last restart chunk)
        test_data["earliest_time"] = '2017-03-08T11:00:01.000000+0000'
        test_data["latest_time"] = None
        self.run_check(config, mocks=test_mocks)
        self.assertFalse(self.continue_after_commit, "As long as we are not done with history, the check should continue")


class TestSplunkQueryInitialHistory(AgentCheckTest):
    """
    Splunk event check should continue where it left off after restart
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {
                'default_initial_history_time_seconds': 86400,
                'default_max_query_chunk_seconds': 3600
            },
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "empty",
                        "parameters": {},
                        'max_initial_history_seconds': 86400,
                        'max_query_chunk_seconds': 3600
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 0,
            "earliest_time": "",
            "latest_time": ""
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": "events"}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])

            if test_data["latest_time"] is None:
                self.assertTrue('dispatch.latest_time' not in args[2])
            elif test_data["latest_time"] != "":
                self.assertEquals(args[2]['dispatch.latest_time'], test_data["latest_time"])

            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_minimal_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        test_data["time"] = time_to_seconds('2017-03-09T00:00:00.000000+0000')

        # Gather initial data
        for slice_num in range(0, 23):
            test_data["earliest_time"] = '2017-03-08T%s:00:00.000000+0000' % (str(slice_num).zfill(2))
            test_data["latest_time"] = '2017-03-08T%s:00:00.000000+0000' % (str(slice_num + 1).zfill(2))
            self.run_check(config, mocks=test_mocks)
            self.assertTrue(self.continue_after_commit, "As long as we are not done with history, the check should continue")

        # Now continue with real-time polling (earliest time taken from last event)
        test_data["earliest_time"] = '2017-03-08T23:00:00.000000+0000'
        test_data["latest_time"] = None
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 2)
        self.assertFalse(self.continue_after_commit, "As long as we are not done with history, the check should continue")


class TestSplunkMaxRestartTime(AgentCheckTest):
    """
    Splunk event check should use the max restart time parameter
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {
                'default_restart_history_time_seconds': 3600,
                'default_max_query_chunk_seconds': 3600
            },
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "empty",
                        "parameters": {},
                        'max_restart_history_seconds': 3600,
                        'max_query_chunk_seconds': 3600
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 0,
            "earliest_time": ""
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": "empty"}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])

            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Initial run with initial time
        test_data["time"] = time_to_seconds('2017-03-08T00:00:00.000000+0000')
        test_data["earliest_time"] = '2017-03-08T00:00:00.000000+0000'
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 0)

        # Restart check and recover data, taking into account the max restart history
        test_data["time"] = time_to_seconds('2017-03-08T12:00:00.000000+0000')
        test_data["earliest_time"] = '2017-03-08T11:00:00.000000+0000'
        test_data["latest_time"] = '2017-03-08T11:00:00.000000+0000'
        self.run_check(config, mocks=test_mocks, force_reload=True)


class TestSplunkKeepTimeOnFailure(AgentCheckTest):
    """
    Splunk event check should keep the same start time when commit fails.
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {
            },
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {},
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 0,
            "earliest_time": ""
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": "events"}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])

            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_minimal_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        self.collect_ok = False

        # Run the check, collect will fail
        test_data["time"] = time_to_seconds('2017-03-08T11:00:00.000000+0000')
        test_data["earliest_time"] = '2017-03-08T11:00:00.000000+0000'
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 2)

        # Make sure we keep the same start time
        self.run_check(config, mocks=test_mocks)


class TestSplunkAdvanceTimeOnSuccess(AgentCheckTest):
    """
    Splunk event check should advance the start time when commit succeeds
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {
            },
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "name": "events",
                        "parameters": {},
                    }],
                    'tags': ["checktag:checktagvalue"]
                }
            ]
        }

        # Used to validate which searches have been executed
        test_data = {
            "time": 0,
            "earliest_time": ""
        }

        def _mocked_current_time_seconds():
            return test_data["time"]

        def _mocked_dispatch_saved_search_do_post(*args, **kwargs):
            class MockedResponse():
                def json(self):
                    return {"sid": "events"}
            earliest_time = args[2]['dispatch.earliest_time']
            if test_data["earliest_time"] != "":
                self.assertEquals(earliest_time, test_data["earliest_time"])

            return MockedResponse()

        test_mocks = {
            '_do_post': _mocked_dispatch_saved_search_do_post,
            '_search': _mocked_minimal_search,
            '_current_time_seconds': _mocked_current_time_seconds,
            '_saved_searches': _mocked_saved_searches
        }

        # Run the check, collect will fail
        test_data["time"] = time_to_seconds('2017-03-08T11:00:00.000000+0000')
        test_data["earliest_time"] = '2017-03-08T11:00:00.000000+0000'
        self.run_check(config, mocks=test_mocks)
        self.assertEqual(len(self.events), 2)

        # Make sure we advance the start time
        test_data["earliest_time"] = '2017-03-08T12:00:00.000000+0000'
        self.run_check(config, mocks=test_mocks)


class TestSplunkWildcardSearches(AgentCheckTest):
    """
    Splunk event check should process minimal response correctly
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "match": "even*",
                        "parameters": {}
                    }],
                    'tags': []
                }
            ]
        }

        data = {
            'saved_searches': []
        }

        def _mocked_saved_searches(*args, **kwargs):
            return data['saved_searches']

        data['saved_searches'] = ["events", "blaat"]
        self.run_check(config, mocks={
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_minimal_search,
            '_saved_searches': _mocked_saved_searches
        })

        self.assertEqual(len(self.check.instance_data['http://localhost:13001'].saved_searches.searches), 1)
        self.assertEqual(len(self.events), 2)

        data['saved_searches'] = []
        self.run_check(config, mocks={
            '_dispatch_saved_search': _mocked_dispatch_saved_search,
            '_search': _mocked_minimal_search,
            '_saved_searches': _mocked_saved_searches
        })
        self.assertEqual(len(self.check.instance_data['http://localhost:13001'].saved_searches.searches), 0)
        self.assertEqual(len(self.events), 0)


class TestSplunkSavedSearchesError(AgentCheckTest):
    """
    Splunk event check should have a service check failure when getting an exception from saved searches
    """
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches': [{
                        "match": "even*",
                        "parameters": {}
                    }],
                    'tags': []
                }
            ]
        }

        def _mocked_saved_searches(*args, **kwargs):
            raise Exception("Boom")

        thrown = False
        try:
            self.run_check(config, mocks={
                '_saved_searches': _mocked_saved_searches
            })
        except CheckException:
            thrown = True
        self.assertTrue(thrown, "Retrieving FATAL message from Splunk should throw.")
        self.assertEquals(self.service_checks[0]['status'], 2, "service check should have status AgentCheck.CRITICAL")


def _mocked_dispatch_saved_search(*args, **kwargs):
    # Sid is equal to search name
    return args[1].name

def _mocked_search(*args, **kwargs):
    # sid is set to saved search name
    sid = args[0]
    return [json.loads(Fixtures.read_file("%s.json" % sid))]

def _mocked_minimal_search(*args, **kwargs):
    # sid is set to saved search name
    sid = args[0]
    return [json.loads(Fixtures.read_file("minimal_%s.json" % sid))]

def _mocked_full_search(*args, **kwargs):
    # sid is set to saved search name
    sid = args[0]
    return [json.loads(Fixtures.read_file("full_%s.json" % sid))]


class TestSplunkEventRespectParallelDispatches(AgentCheckTest):
    CHECK_NAME = 'splunk_event'

    def test_checks(self):
        self.maxDiff = None

        saved_searches_parallel = 2

        config = {
            'init_config': {},
            'instances': [
                {
                    'url': 'http://localhost:13001',
                    'username': "admin",
                    'password': "admin",
                    'saved_searches_parallel': saved_searches_parallel,
                    'saved_searches': [
                        {"name": "savedsearch1", "parameters": {}},
                        {"name": "savedsearch2", "parameters": {}},
                        {"name": "savedsearch3", "parameters": {}},
                        {"name": "savedsearch4", "parameters": {}},
                        {"name": "savedsearch5", "parameters": {}}
                    ]
                }
            ]
        }

        self.expected_sid_increment = 1

        def _mock_dispatch_and_await_search(instance, saved_searches):
            self.assertLessEqual(len(saved_searches), saved_searches_parallel, "Did not respect the configured saved_searches_parallel setting, got value: %i" % len(saved_searches))

            for saved_search in saved_searches:
                result = saved_search.name
                expected = "savedsearch%i" % self.expected_sid_increment
                self.assertEquals(result, expected)
                self.expected_sid_increment += 1

        self.run_check(config, mocks={
            '_dispatch_and_await_search': _mock_dispatch_and_await_search,
            '_saved_searches': _mocked_saved_searches
        })
