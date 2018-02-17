from __future__ import unicode_literals

import contextlib
import os
import shutil
import sys
import tempfile
import uuid

import six
from six import StringIO

from rbtools.utils.filesystem import cleanup_tempfiles, make_tempdir
from rbtools.testing import TestCase


# Immediately store the user's home directory so there's a always a valid
# directory to return to.
OLD_HOMES = [os.environ['HOME']]


class RBTestBase(TestCase):
    """Base class for RBTools tests.

    Its side effect in that it change home directory before test suit will
    run. This is because RBTools actively works with files and almost all
    tests employ file I/O operations.
    """

    def setUp(self):
        # Move the user's home directory out the way so we don't
        # accidentally make changes there
        self.set_user_home_tmp()

    def tearDown(self):
        try:
            self.revert_user_home()
        except OSError:
            self.reset_user_home()
        cleanup_tempfiles()

    def create_tmp_dir(self):
        """Creates and returns a temporary directory."""
        return make_tempdir()

    def chdir_tmp(self, temp_dir=None):
        """Changes current directory to a temporary directory."""
        dirname = make_tempdir(parent=temp_dir)
        os.chdir(dirname)
        return dirname

    def gen_uuid(self):
        """Generates UUID value which can be useful where some unique value
        is required."""
        return str(uuid.uuid4())

    def get_user_home(self):
        """Returns current user's home directory."""
        return os.environ['HOME']

    def reset_cl_args(self, values=[]):
        """Replaces command-line arguments with new ones.

        Useful for testing program's command-line options.
        """
        sys.argv = values

    def reset_user_home(self):
        """Reset the user's home directory.

        Reset the user's home to the known safe home directory.
        """
        os.environ['HOME'] = OLD_HOMES[0]
        os.chdir(os.environ['HOME'])

    def revert_user_home(self):
        """Revert the user's home directory.

        Revert the home directory to what it was when this set of tests
        started.
        """
        global OLD_HOMES

        os.environ['HOME'] = OLD_HOMES.pop()
        # Ensure there's always a safe home to return to
        if not OLD_HOMES:
            OLD_HOMES.append(os.environ['HOME'])
        os.chdir(os.environ['HOME'])

    def set_user_home(self, path):
        """Set home directory of current user."""
        global OLD_HOMES

        OLD_HOMES.append(os.environ['HOME'])
        os.environ['HOME'] = path

    def set_user_home_tmp(self):
        """Set temporary directory as current user's home."""
        self.set_user_home(make_tempdir())

    def catch_output(self, func):
        stdout = sys.stdout
        outbuf = StringIO()
        sys.stdout = outbuf
        func()
        sys.stdout = stdout
        return outbuf.getvalue()

    @contextlib.contextmanager
    def reviewboardrc(self, data, use_temp_dir=False):
        """Manage a temporary .reviewboardrc file.

        Args:
            data (dict)
                A dictionary of key-value pairs to write into the
                .reviewboardrc file.

                A best effort attempt will be made to convert the value into
                an appropriate string.

            use_temp_dir (boolean)
                A boolean that indicates if a temporary directory should be
                created and used as the working directory for the context.
        """
        if use_temp_dir:
            temp_dir = tempfile.mkdtemp()
            cwd = os.getcwd()
            os.chdir(temp_dir)

        with open('.reviewboardrc', 'w') as fp:
            for key, value in six.iteritems(data):
                fp.write('%s = %r\n' % (key, value))

        try:
            yield
        finally:
            if use_temp_dir:
                os.chdir(cwd)
                shutil.rmtree(temp_dir)
