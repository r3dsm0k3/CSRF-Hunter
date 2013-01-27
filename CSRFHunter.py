from IronWASP import *

class CSRFHunter(Module):

        def GetInstance(self):
                m = CSRFHunter()
                m.Name = "CSRFHunter"
                m.Host = "http://www.google.com" #Get from UI
                m.token_name = "auth"  #Get from UI , empty if there are none
                m.Results = []
                m.RequestsWithToken = []
                return m

        def StartModule(self):
                Tools.Trace("Hunting Started","StartModuleOnSession method called")
                for id in range(1,Config.LastTestProxyLogId): #Delegate/sleep through 
                        req = Request.FromProxyLog(id)
                        if req.HostName == self.Host:
                                if has_token_in_request(self,req):
                                        self.RequestsWithToken.append(req)
                                else :
                                        self.Results.append(req)
                #now we have the data populated in the respective arrays,
                #results will have the request which doesnt have token and could be CSRFable.
                #We'll have to do further analysis with the other array of requests
                if self.RequestsWithToken.size:

                        #resend request , modifying the token
                        for req in range(0,self.RequestsWithToken.size):
                                edt_req = modify_token_in_req(self,req,"EDT")
                                del_req = modify_token_in_req(self,req,"DEL")

                                #send requests
                                orig_res = req.Send()
                                IronThread.Sleep(1000)
                                edt_res  = edt_req.Send()
                                IronThread.Sleep(1000)
                                del_res  = del_req.Send()

                                #compare responses
                                min_diff_level = 10 #might have to tweak this value
                                if Tools.DiffLevel(orig_res,edt_res) < min_diff_level :
                                        self.Results.append(edt_req)
                                if Tools.DiffLevel(orig_res,del_res) < min_diff_level :
                                        self.Results.append(del_req)

                #Hopefully we've got the results,show it in a new tab and invoke PoC Generator

        #utility functions
        def modify_token_in_req(self,r,action):
                place_of_token = get_place_of_token_in_request(self,r)

                if place_of_token == "Body":
                        if action == "DEL" :
                                r.Body.Remove(self.token_name)
                        elif action == "EDT" :
                                r.Body.Set(self.token_name,"ignore_me")

                elif place_of_token == "Query":
                            if action == "DEL" :
                                r.Query.Remove(self.token_name)
                        elif action == "EDT" :
                                r.Query.Set(self.token_name,"ignore_me")

                elif place_of_token == "Header":
                            if action == "DEL" :
                                r.Header.Remove(self.token_name)
                        elif action == "EDT" :
                                r.Header.Set(self.token_name,"ignore_me")

                elif place_of_token == "Cookie":
                            if action == "DEL" :
                                r.Cookie.Remove(self.token_name)
                        elif action == "EDT" :
                                r.Cookie.Set(self.token_name,"ignore_me")
                return r

        def get_place_of_token_in_request(self,r):
                ret = "none"
                if r.Body.Has(self.token_name):
                        ret = "Body"
                elif r.Query.Has(self.token_name):
                        ret = "Query"
                elif r.Headers.Has(self.token_name):
                        ret = "Header"
                elif r.Cookie.Has(self.token_name):
                        ret = "Cookie"
                return ret

        def has_token_in_request(self,r):
                ret = get_place_of_token_in_request(self,r)
                if not ret == "none" :
                        return true
                else :
                        return false


m = CSRFHunter()
#m.StartModule()
Module.Add(m.GetInstance())