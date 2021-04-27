event zeek_init()
    {
    local a1 = SumStats::Reducer($stream="all", $apply=set(SumStats::SUM));
    local a2 = SumStats::Reducer($stream="404", $apply=set(SumStats::SUM));
    local a3 = SumStats::Reducer($stream="404url", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="work",
                      $epoch=10min,
                      $reducers=set(a1,a2,a3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        	local b1 = result["all"];
                        	local b2 = result["404"];
	        	         	local b3 = result["404url"];
	        	         	if (b2$sum>2)
	        	            {
	        	             	if ((b2$sum/b1$sum)>0.2)
	        	             	{
	        	 	            	if((b3$unique/b2$sum)>0.5)
	        		               	{
	        		            		print fmt("%s is a scanner with %.0f scan attemps on %d urls", key$host, b2$sum, b3$unique);
                                	}
	        	              	}
	        	             }
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string) {
    SumStats::observe("all", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) {
        SumStats::observe("404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("404url", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}
