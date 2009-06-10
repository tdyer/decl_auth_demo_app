
authorization do

  role :guest do
    # allow guests to access the conference controller's index and show actions
    # /conferences/ AND conferences/1 URIs.
    # iff The conferences are published, i.e.(@conference.published == true). 

    # NOTE: @conference is build by before_filter :load_conference in the 
    # conference controller.
    # (see *1 below for detailed description)
    has_permission_on :conferences, :to => :read do
      if_attribute :published => true
    end

    # allow guests to access to the talk controllers index and show actions
    # conferences/2/talks and conferences/2/talk/3 URIs
    # iff The talks are about a published conference,i.e.
    # (@conference.published == true). 

    # NOTE: @conference is build by before_filter :load_conference in the talk 
    # controller.
    has_permission_on :talks, :to => :read do
      # look to see if read priviledge in the conference context is already
      # defined. If so subsitute it's body in here.
      if_permitted_to :read, :conference
      # yes, read priviledge on conference context is defined above so it's 
      # body is used here.
      # aka:
      # if_attribute :conference => {:published => true}      
    end
    
    # allow guests to access to the talk controllers index and show actions
    # conferences/2/talks and conferences/2/talk/3 URIs

    has_permission_on :users, :to => :create

    has_permission_on :authorization_rules, :to => :read
    has_permission_on :authorization_usages, :to => :read
  end
  
  role :user do
    # includes all the guest permissions defined above
    includes :guest

    # allows users to access conference_attendee controller's new action
    # /conferences/1/conference_attendees/new URI
    # iff the conference is  published.
    # - @conference_attendee.user == current_user (always true, 
    # see new_conference_attendee_from_params). don't think we need this role?
    # AND
    # - @conference_attendee.conference.published == true
    has_permission_on :conference_attendees, :to => :create, :join_by => :and do
      if_attribute :user => is {user}
      # look to see if read permission in the conference context is already
      # defined. If so subsitute it in here.
      if_permitted_to :read, :conference
      # aka: 
      # if_attribute :conference => {:published => true}
      # because read permisssion on the conference context is defined above
      # has_permission_on :conferences, :to => :read do' above)
      #   if_attribute :published => true
      # end   
      
    end

    # allows users access to the conference_attedee controller's delete action
    # /conference/1/conference_attendees/delete/3
    # iff the current user is this conference attendee
    # @conference_attendee.user == current_user
    has_permission_on :conference_attendees, :to => :delete do
      if_attribute :user => is {user}
    end
    
    # allows a user access to the talk_attendee controller's new acction
    # /talks/3/talk_attendees/new URI
    # iff the conference that this talk belongs has the current user registered
    #,i.e. current user is conference attendee.
    # @talk_attendee.talk.conference.attendees.includes? current_user
    has_permission_on :talk_attendees, :to => :create do
      if_attribute :talk => { :conference => { :attendees => contains {user} }},
          :user => is {user}
    end

    has_permission_on :talk_attendees, :to => :delete do
      if_attribute :user => is {user}
    end
  end
  
  role :conference_organizer do
    has_permission_on :conferences do
      to :manage
      # if...
    end
    has_permission_on [:conference_attendees, :talks, :talk_attendees], :to => :manage
  end
  
  role :admin do
    has_permission_on [:conferences, :users, :talks], :to => :manage
    has_permission_on :authorization_rules, :to => :read
    has_permission_on :authorization_usages, :to => :read
  end
end

privileges do
  privilege :manage, :includes => [:create, :read, :update, :delete]
  privilege :read, :includes => [:index, :show]
  privilege :create, :includes => :new
  privilege :update, :includes => :edit
  privilege :delete, :includes => :destroy
end

# *1
  # guests have permission to call the index and show in the conference controller 
  # iff the @conference attribute in the conference controller published method 
  # returns true. 
  # EX: GET request to conferences/1 will:
  # 1) before_filter :load_conference, :only => [:show, ...]
  #   1.1) create the @conference obj in the conference controller's 
  #        load_conference method.
  # 2) filter_access_to :all, :attribute_check => true.
  #   2.1) Find the guest role for the current_user.
  #   2.2) Find context for the ConferenceController in the guest role's 
  #        permissions..
  #        has_permission :conferences
  #   2.3) Find the priviledge for the ConferenceController show action.
  #        has_permission :conferences, :to => read
  #   2.3) Find the method to call on the @conference attribute.
  #        has_permission :conferences, :to => read do
  #          if_attribute :published => true
  #   3.0) Call the @conference.published method
  #        - if return true then access allowed.
  #        - else access denied.
  # For /conferences/1 => access is allowed.
  # For /conferences/5 => access is denied because Conference.find(5).published 
  # returns false.
