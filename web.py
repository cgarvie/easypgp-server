import os

from views import *
from app import app

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

# Default port:
#if __name__ == '__main__':
#    app.run()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    #app.run(host='127.0.0.1', port=port, debug=True) # local
    app.run(host='0.0.0.0', port=port, debug=True) # heroku
