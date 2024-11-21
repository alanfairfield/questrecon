from questrecon import Scanner


#Object for service detection inheriting methods from the Scanner object class
class ServiceDetection(Scanner):
    def __init__(self, target=None, hosts_file=None, output_dir=None, services=None):
        super().__init__(target, output_dir, hosts_file)
        self.services = services
