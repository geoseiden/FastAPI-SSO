import logging

logging.basicConfig(filename="main.log",
                    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
                    filemode='a')

logger = logging.getLogger()
logger.setLevel(logging.INFO)